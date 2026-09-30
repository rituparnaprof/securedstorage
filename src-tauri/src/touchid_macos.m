// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 rituparnaprof
// SecuredStorage - macOS Native Touch ID & LocalAuthentication Bridge

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
