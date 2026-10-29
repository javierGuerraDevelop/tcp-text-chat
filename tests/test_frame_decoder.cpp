#include "tcp_chat/frame.h"

#include <QTest>
#include <QtEndian>

#include <random>

namespace {

using tcp_chat::protocol::Envelope;
using tcp_chat::protocol::ErrorCode;
using tcp_chat::protocol::FrameDecoder;
using tcp_chat::protocol::MessageType;

/// Creates a four-byte big-endian frame header for test input.
QByteArray raw_header(quint32 payload_size)
{
    QByteArray header;
    header.resize(4);
    qToBigEndian(payload_size, header.data());
    return header;
}

/// Creates a raw frame independently of the production encoder.
QByteArray raw_frame(const QByteArray& payload)
{
    QByteArray frame = raw_header(static_cast<quint32>(payload.size()));
    frame.append(payload);
    return frame;
}

} // namespace

/// Verifies bounded framing and incremental stream decoding.
class FrameDecoderTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks the exact length-prefix byte order.
    void encodesBigEndianLength();
    /// Checks the inclusive maximum payload boundary.
    void acceptsMaximumSizePayload();
    /// Provides payloads that cannot be framed.
    void rejectsInvalidEncodedPayloads_data();
    /// Checks empty and oversized payload rejection.
    void rejectsInvalidEncodedPayloads();
    /// Checks headers and bodies split across reads.
    void decodesFragmentedFrame();
    /// Checks decoding after every individual byte append.
    void decodesSingleByteStream();
    /// Checks multiple frames returned from one buffer.
    void decodesCoalescedFrames();
    /// Checks rejection of a zero length prefix.
    void rejectsZeroLengthFrame();
    /// Checks rejection from the header without a payload.
    void rejectsOversizedHeader();
    /// Checks sticky errors and explicit decoder reset.
    void keepsErrorUntilReset();
    /// Checks every possible two-part split of a frame.
    void testsEverySplitPosition();
    /// Checks deterministic randomized chunk boundaries and coalescing.
    void decodesDeterministicRandomChunking();
    /// Checks envelope JSON encoding through the frame codec.
    void roundTripsEnvelopeThroughFrameCodec();
    /// Checks that JSON envelopes cannot exceed the frame limit.
    void rejectsOversizedEnvelope();
};

void FrameDecoderTest::encodesBigEndianLength()
{
    tcp_chat::protocol::ProtocolError error;
    const auto encoded = tcp_chat::protocol::encode_frame(QByteArrayLiteral("abc"), &error);
    QVERIFY(encoded.has_value());
    QCOMPARE(*encoded, QByteArray::fromHex("00000003616263"));
    QCOMPARE(error.code, ErrorCode::None);
}

void FrameDecoderTest::acceptsMaximumSizePayload()
{
    const QByteArray payload(tcp_chat::protocol::maximum_frame_size, 'x');
    const auto encoded = tcp_chat::protocol::encode_frame(payload);
    QVERIFY(encoded.has_value());
    QCOMPARE(encoded->size(), tcp_chat::protocol::maximum_frame_size + 4);

    FrameDecoder decoder;
    decoder.append(*encoded);
    const auto decoded = decoder.next_frame();
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, payload);
    QVERIFY(decoder.error() == nullptr);
}

void FrameDecoderTest::rejectsInvalidEncodedPayloads_data()
{
    QTest::addColumn<QByteArray>("payload");

    QTest::newRow("empty") << QByteArray();
    QTest::newRow("oversized") << QByteArray(tcp_chat::protocol::maximum_frame_size + 1, 'x');
}

void FrameDecoderTest::rejectsInvalidEncodedPayloads()
{
    QFETCH(QByteArray, payload);

    tcp_chat::protocol::ProtocolError error;
    const auto encoded = tcp_chat::protocol::encode_frame(payload, &error);
    QVERIFY(!encoded.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidFrame);
    QVERIFY(!error.message.isEmpty());
}

void FrameDecoderTest::decodesFragmentedFrame()
{
    const QByteArray stream = raw_frame(QByteArrayLiteral("fragmented payload"));
    FrameDecoder decoder;

    decoder.append(QByteArrayView(stream.constData(), 2));
    QVERIFY(!decoder.next_frame().has_value());
    decoder.append(QByteArrayView(stream.constData() + 2, 5));
    QVERIFY(!decoder.next_frame().has_value());
    decoder.append(QByteArrayView(stream.constData() + 7, stream.size() - 7));

    const auto decoded = decoder.next_frame();
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, QByteArrayLiteral("fragmented payload"));
    QVERIFY(!decoder.next_frame().has_value());
    QVERIFY(decoder.error() == nullptr);
}

void FrameDecoderTest::decodesSingleByteStream()
{
    const QList<QByteArray> expected = { QByteArrayLiteral("one"), QByteArrayLiteral("two"), QByteArrayLiteral("three") };
    QByteArray stream;
    for (const QByteArray& payload : expected) {
        stream.append(raw_frame(payload));
    }

    QList<QByteArray> actual;
    FrameDecoder decoder;
    for (qsizetype index = 0; index < stream.size(); ++index) {
        decoder.append(QByteArrayView(stream.constData() + index, 1));
        while (const auto frame = decoder.next_frame()) {
            actual.append(*frame);
        }
    }

    QCOMPARE(actual, expected);
    QVERIFY(decoder.error() == nullptr);
}

void FrameDecoderTest::decodesCoalescedFrames()
{
    QByteArray stream = raw_frame(QByteArrayLiteral("first"));
    stream.append(raw_frame(QByteArrayLiteral("second")));

    FrameDecoder decoder;
    decoder.append(stream);
    const auto first  = decoder.next_frame();
    const auto second = decoder.next_frame();
    QVERIFY(first.has_value());
    QVERIFY(second.has_value());
    QCOMPARE(*first, QByteArrayLiteral("first"));
    QCOMPARE(*second, QByteArrayLiteral("second"));
    QVERIFY(!decoder.next_frame().has_value());
}

void FrameDecoderTest::rejectsZeroLengthFrame()
{
    FrameDecoder decoder;
    decoder.append(raw_header(0));
    QVERIFY(!decoder.next_frame().has_value());
    QVERIFY(decoder.error() != nullptr);
    QCOMPARE(decoder.error()->code, ErrorCode::InvalidFrame);
}

void FrameDecoderTest::rejectsOversizedHeader()
{
    FrameDecoder decoder;
    decoder.append(raw_header(static_cast<quint32>(tcp_chat::protocol::maximum_frame_size + 1)));
    QVERIFY(!decoder.next_frame().has_value());
    QVERIFY(decoder.error() != nullptr);
    QCOMPARE(decoder.error()->code, ErrorCode::InvalidFrame);
}

void FrameDecoderTest::keepsErrorUntilReset()
{
    FrameDecoder decoder;
    decoder.append(raw_header(0));
    QVERIFY(!decoder.next_frame().has_value());
    QVERIFY(decoder.error() != nullptr);

    decoder.append(raw_frame(QByteArrayLiteral("ignored")));
    QVERIFY(!decoder.next_frame().has_value());

    decoder.reset();
    QVERIFY(decoder.error() == nullptr);
    decoder.append(raw_frame(QByteArrayLiteral("accepted")));
    const auto decoded = decoder.next_frame();
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, QByteArrayLiteral("accepted"));
}

void FrameDecoderTest::testsEverySplitPosition()
{
    const QByteArray payload(256, 'p');
    const QByteArray stream = raw_frame(payload);

    for (qsizetype split = 1; split < stream.size(); ++split) {
        FrameDecoder decoder;
        decoder.append(QByteArrayView(stream.constData(), split));
        QVERIFY(!decoder.next_frame().has_value());
        decoder.append(QByteArrayView(stream.constData() + split, stream.size() - split));

        const auto decoded = decoder.next_frame();
        QVERIFY(decoded.has_value());
        QCOMPARE(*decoded, payload);
        QVERIFY(!decoder.next_frame().has_value());
        QVERIFY(decoder.error() == nullptr);
    }
}

void FrameDecoderTest::decodesDeterministicRandomChunking()
{
    std::mt19937 generator { 12345 };
    std::uniform_int_distribution<int> payload_length { 1, 512 };
    std::uniform_int_distribution<int> chunk_length { 1, 37 };

    for (int iteration = 0; iteration < 50; ++iteration) {
        QList<QByteArray> expected;
        QByteArray stream;
        for (int message = 0; message < 4; ++message) {
            const QByteArray payload(payload_length(generator), static_cast<char>('a' + message));
            expected.append(payload);
            stream.append(raw_frame(payload));
        }

        QList<QByteArray> actual;
        FrameDecoder decoder;
        qsizetype offset = 0;
        while (offset < stream.size()) {
            const qsizetype count = qMin<qsizetype>(chunk_length(generator), stream.size() - offset);
            decoder.append(QByteArrayView(stream.constData() + offset, count));
            offset += count;
            while (const auto frame = decoder.next_frame()) {
                actual.append(*frame);
            }
            QVERIFY(decoder.error() == nullptr);
        }
        QCOMPARE(actual, expected);
    }
}

void FrameDecoderTest::roundTripsEnvelopeThroughFrameCodec()
{
    Envelope original;
    original.type       = MessageType::Pong;
    original.request_id = QStringLiteral("request-7");
    original.payload    = QJsonObject { { QStringLiteral("status"), QStringLiteral("ready") } };

    tcp_chat::protocol::ProtocolError error;
    const auto encoded = tcp_chat::protocol::encode_envelope(original, &error);
    QVERIFY(encoded.has_value());

    FrameDecoder decoder;
    decoder.append(*encoded);
    const auto payload = decoder.next_frame();
    QVERIFY(payload.has_value());
    const auto decoded = tcp_chat::protocol::decode_envelope(*payload, &error);
    QVERIFY(decoded.has_value());
    QCOMPARE(*decoded, original);
}

void FrameDecoderTest::rejectsOversizedEnvelope()
{
    Envelope envelope;
    envelope.payload = QJsonObject {
        { QStringLiteral("text"), QString(tcp_chat::protocol::maximum_frame_size, QLatin1Char('x')) },
    };

    tcp_chat::protocol::ProtocolError error;
    const auto encoded = tcp_chat::protocol::encode_envelope(envelope, &error);
    QVERIFY(!encoded.has_value());
    QCOMPARE(error.code, ErrorCode::InvalidFrame);
}

QTEST_GUILESS_MAIN(FrameDecoderTest)

#include "test_frame_decoder.moc"
