"""Virtual Xbox 360 controller via ViGEmBus (using vgamepad's bundled ViGEmClient)."""

import logging

log = logging.getLogger("xdongle.vpad")


class VirtualPad:
    def __init__(self, on_rumble):
        import vgamepad as vg  # imported lazily so the rest can be tested without ViGEm
        self._on_rumble = on_rumble
        self.pad = vg.VX360Gamepad()
        self.pad.register_notification(callback_function=self._notification)
        log.info("Virtual Xbox 360 controller plugged in")

    def _notification(self, client, target, large_motor, small_motor, led_number, user_data):
        try:
            self._on_rumble(int(large_motor), int(small_motor))
        except Exception:
            log.exception("rumble callback failed")

    def update(self, buttons, lt, rt, lx, ly, rx, ry):
        r = self.pad.report
        r.wButtons = buttons
        r.bLeftTrigger = lt
        r.bRightTrigger = rt
        r.sThumbLX = lx
        r.sThumbLY = ly
        r.sThumbRX = rx
        r.sThumbRY = ry
        self.pad.update()

    def close(self):
        try:
            self.pad.unregister_notification()
        except Exception:
            pass
        try:
            self.pad.reset()
            self.pad.update()
        except Exception:
            pass
        # vgamepad unplugs the target when the object is destroyed
        del self.pad
        log.info("Virtual Xbox 360 controller unplugged")
