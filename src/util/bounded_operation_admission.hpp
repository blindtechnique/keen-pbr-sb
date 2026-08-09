#pragma once

#include <cstddef>
#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace keen_pbr3 {

// Thread-safe, exception-safe admission for a small number of expensive
// operations. A lease is copyable so it can cross std::function boundaries;
// the reservation is released exactly once when the final copy is destroyed.
class BoundedOperationAdmission {
private:
    struct State {
        explicit State(std::size_t limit_value) : limit(limit_value) {}

        std::mutex mutex;
        const std::size_t limit;
        std::size_t active{0};
        bool accepting{true};
    };

    struct Token {
        explicit Token(std::shared_ptr<State> state_value)
            : state(std::move(state_value)) {}

        ~Token() noexcept {
            if (!state) {
                return;
            }
            std::lock_guard<std::mutex> lock(state->mutex);
            if (state->active > 0) {
                --state->active;
            }
        }

        std::shared_ptr<State> state;
    };

public:
    class Lease {
    public:
        Lease() noexcept = default;

        explicit operator bool() const noexcept {
            return static_cast<bool>(token_);
        }

        void reset() noexcept {
            token_.reset();
        }

    private:
        friend class BoundedOperationAdmission;

        explicit Lease(std::shared_ptr<Token> token) noexcept
            : token_(std::move(token)) {}

        std::shared_ptr<Token> token_;
    };

    explicit BoundedOperationAdmission(std::size_t limit)
        : state_(std::make_shared<State>(limit)) {}

    BoundedOperationAdmission(const BoundedOperationAdmission&) = delete;
    BoundedOperationAdmission& operator=(const BoundedOperationAdmission&) = delete;

    std::optional<Lease> try_acquire() {
        std::lock_guard<std::mutex> lock(state_->mutex);
        if (!state_->accepting || state_->active >= state_->limit) {
            return std::nullopt;
        }

        ++state_->active;
        try {
            return Lease{std::make_shared<Token>(state_)};
        } catch (...) {
            --state_->active;
            throw;
        }
    }

    void shutdown() noexcept {
        std::lock_guard<std::mutex> lock(state_->mutex);
        state_->accepting = false;
    }

    std::size_t active() const noexcept {
        std::lock_guard<std::mutex> lock(state_->mutex);
        return state_->active;
    }

private:
    std::shared_ptr<State> state_;
};

} // namespace keen_pbr3
