from truegaze.plugins.adobe_mobile_sdk import AdobeMobileSdkPlugin
from truegaze.plugins.firebase import FirebasePlugin
from truegaze.plugins.weak_key import WeakKeyPlugin

# List of active plugins - when developing a new plugin, it should be added here.
# BasePlugin should never be added to this list.
ACTIVE_PLUGINS = [
    AdobeMobileSdkPlugin,
    FirebasePlugin,
    WeakKeyPlugin
]