# Expected Semantic Changes

## Permission
- Permission: android.permission.RECEIVE_BOOT_COMPLETED
- Expected change: removed

## Component
- Component: de.audioattack.openlink.conf.PackageChangeBroadcastReceiver
- Expected change: enabled → disabled

## Everything else
Expected unchanged:
- all other permissions
- all other components
- manifest attributes unrelated to the selected component
- network endpoints
- DEX classes
- DEX methods/bytecode
- native libraries
