// SPDX-License-Identifier: GPL-3.0-or-later
/*
 * SecuredStorage - PQC-Compliant Offline Password Vault
 * Copyright (C) 2026 rituparnaprof
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#import <Foundation/Foundation.h>
#import <LocalAuthentication/LocalAuthentication.h>

/**
 * Trigger native macOS Touch ID biometric prompt
 * Returns:
 *   1 = Authentication succeeded
 *   0 = User canceled or biometric authentication failed
 *  -1 = Biometrics not supported or not enrolled on this hardware
 */
int evaluate_macos_touch_id(const char* reason_utf8) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSError *error = nil;
        NSString *nsReason = [NSString stringWithUTF8String:reason_utf8];

        // Explicitly enforce zero allowable reuse duration:
        // Ensures macOS MUST prompt for the physical finger touch on every verification
        context.touchIDAuthenticationAllowableReuseDuration = 0.0;

        // First test if biometric authentication is available on this Mac
        LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
        if (![context canEvaluatePolicy:policy error:&error]) {
            // Fallback to device owner authentication (system password / Apple Watch)
            policy = LAPolicyDeviceOwnerAuthentication;
            if (![context canEvaluatePolicy:policy error:&error]) {
                return -1; // Not supported or unavailable
            }
        }

        __block int authResult = 0;
        dispatch_semaphore_t sem = dispatch_semaphore_create(0);

        [context evaluatePolicy:policy
                localizedReason:nsReason
                          reply:^(BOOL success, NSError * _Nullable __unused authError) {
            (void)authError;
            if (success) {
                authResult = 1;
            } else {
                authResult = 0;
            }
            dispatch_semaphore_signal(sem);
        }];

        dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
        return authResult;
    }
}
