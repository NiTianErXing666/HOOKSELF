int WaitForStatusByte(int fd, uint32_t timeout_ms, char* status) noexcept {
    if (fd < 0 || status == nullptr) {
        return EINVAL;
    }
    const int64_t started_ns = MonotonicNanoseconds();
    if (started_ns <= 0) {
        return EIO;
    }
    const int64_t deadline_ns =
            started_ns + static_cast<int64_t>(timeout_ms) * 1000000LL;
    pollfd descriptor{fd, static_cast<short>(POLLIN | POLLHUP), 0};
    for (;;) {
        const int64_t now_ns = MonotonicNanoseconds();
        if (now_ns <= 0) {
            return EIO;
        }
        if (now_ns >= deadline_ns) {
            return ETIMEDOUT;
        }
        const int64_t remaining_ns = deadline_ns - now_ns;
        int64_t remaining_ms = (remaining_ns + 999999LL) / 1000000LL;
        if (remaining_ms > INT32_MAX) {
            remaining_ms = INT32_MAX;
        }
        descriptor.revents = 0;
        const int poll_result = poll(
                &descriptor, 1, static_cast<int>(remaining_ms));
        if (poll_result == 0) {
            return ETIMEDOUT;
        }
        if (poll_result < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno;
        }
        const ssize_t bytes = read(fd, status, 1);
        if (bytes == 1) {
            return 0;
        }
        if (bytes < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        return EPIPE;
    }
}

void CloseControllerFds(ResidentSessionController* controller) noexcept {
    if (controller->control_event_fd >= 0) {
        (void)CloseFdObject(controller->control_event_fd,
                            controller->control_event_identity);
    }
    if (controller->status_read_fd >= 0) {
        (void)CloseFdObject(controller->status_read_fd,
                            controller->status_read_identity);
    }
    controller->control_event_fd = -1;
    controller->status_read_fd = -1;
    ClearFdObjectIdentity(&controller->control_event_identity);
    ClearFdObjectIdentity(&controller->status_read_identity);
}

int RestoreDumpable(ResidentSessionController* controller) noexcept {
    int first_error = 0;
    if (controller->ptracer_configured != 0) {
        if (prctl(kPrSetPtracer, 0, 0, 0, 0) != 0) {
            first_error = errno;
        }
    }
    const int desired_dumpable =
            controller->ptrace_view_enabled != 0 &&
                    controller->logical_dumpable >= 0
                    ? controller->logical_dumpable
                    : controller->original_dumpable;
    if (desired_dumpable >= 0) {
        if (prctl(PR_SET_DUMPABLE, desired_dumpable, 0, 0, 0) != 0) {
            if (first_error == 0) {
                first_error = errno;
            }
        } else {
            const int restored = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
            if (restored != desired_dumpable && first_error == 0) {
                first_error = restored < 0 ? errno : EIO;
            }
        }
    }
    if (controller->ptrace_view_enabled != 0 &&
        controller->ptracer_configured != 0 &&
        controller->logical_ptracer != 0) {
        const int logical_ptracer = controller->logical_ptracer;
        bool exists = logical_ptracer == -1;
        if (logical_ptracer > 0) {
            exists = kill(logical_ptracer, 0) == 0 || errno == EPERM;
            if (exists && controller->logical_ptracer_start_time != 0) {
                uint64_t current_start_time = 0;
                exists = hookself::platform::ReadProcessStartTime(
                                 logical_ptracer, &current_start_time) == 0 &&
                         current_start_time ==
                                 controller->logical_ptracer_start_time;
            }
        }
        if (exists &&
            prctl(kPrSetPtracer,
                  logical_ptracer == -1
                          ? static_cast<unsigned long>(-1)
                          : static_cast<unsigned long>(logical_ptracer),
                  0, 0, 0) != 0 &&
            first_error == 0) {
            first_error = errno;
        }
    }
    return first_error;
}

int ReapTracer(pid_t tracer_pid, bool force_kill,
               uint32_t timeout_ms) noexcept {
    if (tracer_pid <= 0) {
        return 0;
    }
    const int64_t started_ns = MonotonicNanoseconds();
    if (started_ns <= 0) {
        return EIO;
    }
    const int64_t deadline_ns =
            started_ns + static_cast<int64_t>(timeout_ms) * 1000000LL;
    bool kill_sent = false;
    int status = 0;
    for (;;) {
        const pid_t waited = waitpid(tracer_pid, &status, WNOHANG);
        if (waited == tracer_pid) {
            return 0;
        }
        if (waited < 0) {
            if (errno == EINTR) {
                continue;
            }
            return errno == ECHILD ? 0 : errno;
        }
        if (force_kill && !kill_sent) {
            if (kill(tracer_pid, SIGKILL) != 0 && errno != ESRCH) {
                return errno;
            }
            kill_sent = true;
        }
        const int64_t now_ns = MonotonicNanoseconds();
        if (now_ns <= 0) {
            return EIO;
        }
        if (now_ns >= deadline_ns) {
            return ETIMEDOUT;
        }
        hookself::platform::RawSleepOneMillisecond();
    }
}

}  // namespace
