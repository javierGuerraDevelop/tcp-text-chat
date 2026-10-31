#include "server/auth/attempt_limiter.h"

#include <QTest>

#include <limits>

namespace {

using tcp_chat::auth::AttemptLimiter;

/// Verifies fixed-window authentication attempt limiting with injected timestamps.
class AttemptLimiterTest : public QObject {
    Q_OBJECT

private slots:
    /// Checks that the first nonnegative timestamp starts a window.
    void firstAttemptStartsWindow();
    /// Checks that attempts at and above the configured limit are handled exactly.
    void enforcesExactLimit();
    /// Checks that the window expires at its exclusive end boundary.
    void expiresAtExactBoundary();
    /// Checks that an attempt in the next window resets the limit.
    void resetsInNextWindow();
    /// Checks that negative timestamps never change limiter state.
    void rejectsNegativeTimestamps();
    /// Checks that backward timestamps start a fresh window safely.
    void startsNewWindowForBackwardTime();
    /// Checks arithmetic near the largest representable timestamp.
    void handlesTimestampLimits();
    /// Provides nonpositive attempt and window limits.
    void rejectsInvalidConfiguration_data();
    /// Checks that invalid configuration fails closed.
    void rejectsInvalidConfiguration();
    /// Checks the accepted-attempt count through denial and reset.
    void tracksCount();
};

void AttemptLimiterTest::firstAttemptStartsWindow()
{
    AttemptLimiter limiter(2, 100);

    QCOMPARE(limiter.count(), 0);
    QVERIFY(limiter.allow(0));
    QCOMPARE(limiter.count(), 1);
    QVERIFY(!limiter.expired(99));
}

void AttemptLimiterTest::enforcesExactLimit()
{
    AttemptLimiter limiter(2, 100);

    QVERIFY(limiter.allow(100));
    QVERIFY(limiter.allow(199));
    QVERIFY(!limiter.allow(199));
    QCOMPARE(limiter.count(), 2);
}

void AttemptLimiterTest::expiresAtExactBoundary()
{
    AttemptLimiter limiter(1, 100);

    QVERIFY(!limiter.expired(-1));
    QVERIFY(limiter.expired(0));
    QVERIFY(limiter.allow(100));
    QVERIFY(!limiter.expired(199));
    QVERIFY(limiter.expired(200));
    QCOMPARE(limiter.count(), 1);
}

void AttemptLimiterTest::resetsInNextWindow()
{
    AttemptLimiter limiter(1, 100);

    QVERIFY(limiter.allow(100));
    QVERIFY(!limiter.allow(199));
    QVERIFY(limiter.allow(200));
    QCOMPARE(limiter.count(), 1);
}

void AttemptLimiterTest::rejectsNegativeTimestamps()
{
    AttemptLimiter limiter(2, 100);

    QVERIFY(!limiter.allow(-1));
    QCOMPARE(limiter.count(), 0);
    QVERIFY(!limiter.expired(-1));
    QVERIFY(limiter.allow(100));
    QVERIFY(!limiter.allow(-100));
    QVERIFY(!limiter.expired(-100));
    QCOMPARE(limiter.count(), 1);
    QVERIFY(limiter.allow(101));
    QCOMPARE(limiter.count(), 2);
}

void AttemptLimiterTest::startsNewWindowForBackwardTime()
{
    AttemptLimiter limiter(1, 100);

    QVERIFY(limiter.allow(1000));
    QVERIFY(!limiter.allow(1099));
    QVERIFY(!limiter.expired(999));
    QVERIFY(limiter.allow(999));
    QCOMPARE(limiter.count(), 1);
    QVERIFY(!limiter.allow(1000));
}

void AttemptLimiterTest::handlesTimestampLimits()
{
    const auto maximum = std::numeric_limits<qint64>::max();
    AttemptLimiter limiter(2, 1000);

    QVERIFY(limiter.allow(maximum - 1));
    QVERIFY(limiter.allow(maximum));
    QVERIFY(!limiter.expired(maximum));
    QVERIFY(limiter.allow(maximum - 2));
    QCOMPARE(limiter.count(), 1);
}

void AttemptLimiterTest::rejectsInvalidConfiguration_data()
{
    QTest::addColumn<int>("maximumAttempts");
    QTest::addColumn<qint64>("windowMs");

    QTest::newRow("zero attempts") << 0 << qint64(100);
    QTest::newRow("negative attempts") << -1 << qint64(100);
    QTest::newRow("zero window") << 1 << qint64(0);
    QTest::newRow("negative window") << 1 << qint64(-1);
}

void AttemptLimiterTest::rejectsInvalidConfiguration()
{
    QFETCH(int, maximumAttempts);
    QFETCH(qint64, windowMs);

    AttemptLimiter limiter(maximumAttempts, windowMs);
    QVERIFY(!limiter.allow(0));
    QVERIFY(!limiter.allow(100));
    QCOMPARE(limiter.count(), 0);
}

void AttemptLimiterTest::tracksCount()
{
    AttemptLimiter limiter(3, 100);

    QCOMPARE(limiter.count(), 0);
    QVERIFY(limiter.allow(10));
    QCOMPARE(limiter.count(), 1);
    QVERIFY(limiter.allow(11));
    QCOMPARE(limiter.count(), 2);
    QVERIFY(limiter.allow(12));
    QCOMPARE(limiter.count(), 3);
    QVERIFY(!limiter.allow(13));
    QCOMPARE(limiter.count(), 3);
    QVERIFY(limiter.allow(110));
    QCOMPARE(limiter.count(), 1);
}

} // namespace

QTEST_GUILESS_MAIN(AttemptLimiterTest)

#include "test_attempt_limiter.moc"
