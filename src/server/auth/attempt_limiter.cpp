#include "attempt_limiter.h"

namespace tcp_chat::auth {

AttemptLimiter::AttemptLimiter(int maximum_attempts, qint64 window_ms)
    : maximum_attempts_(maximum_attempts)
    , window_ms_(window_ms)
{
}

bool AttemptLimiter::allow(qint64 now)
{
    if (now < 0 || maximum_attempts_ <= 0 || window_ms_ <= 0) {
        return false;
    }

    if (window_start_ < 0 || now < window_start_ || now - window_start_ >= window_ms_) {
        window_start_ = now;
        count_        = 0;
    }

    if (count_ >= maximum_attempts_) {
        return false;
    }

    ++count_;
    return true;
}

bool AttemptLimiter::expired(qint64 now) const
{
    if (now < 0) {
        return false;
    }
    if (window_start_ < 0) {
        return true;
    }

    return now >= window_start_ && now - window_start_ >= window_ms_;
}

int AttemptLimiter::count() const
{
    return count_;
}

} // namespace tcp_chat::auth
