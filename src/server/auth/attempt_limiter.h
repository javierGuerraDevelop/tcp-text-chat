#pragma once

#include <QtGlobal>

namespace tcp_chat::auth {

/// Limits authentication attempts to fixed timestamp windows on one event-loop thread.
class AttemptLimiter {
public:
    /// Creates a limiter; nonpositive limits defensively reject every attempt.
    AttemptLimiter(int maximum_attempts, qint64 window_ms);

    /// Admits an attempt in the current window; backward time starts a new window and negative time is rejected.
    bool allow(qint64 now);

    /// Reports whether a nonnegative timestamp is at or beyond the window end without changing state.
    bool expired(qint64 now) const;

    /// Returns the number of admitted attempts in the current window.
    int count() const;

private:
    int maximum_attempts_;
    qint64 window_ms_;
    qint64 window_start_ = -1;
    int count_           = 0;
};

} // namespace tcp_chat::auth
