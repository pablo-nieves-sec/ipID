"""
categories.py - the single source of truth for device categories.

Before this module existed, the classifier emitted names like "Printer" and
"Endpoint (Windows)" while the coverage logic and the dashboard expected
"Printers / MFPs" and "Windows Endpoints". The names never matched, so
missing-EDR was never flagged for a real Windows or Mac host (the demo seed
data used the second naming, which hid the bug). Everything now imports these
constants so the names can only ever agree.
"""


class Cat:
    WINDOWS = "Windows Endpoints"
    MAC = "Mac Endpoints"
    LINUX = "Endpoint/Server (Linux)"
    SERVER_HV = "Servers / Hypervisors"
    SERVER = "Server"
    BMC = "Server/Mgmt (BMC)"
    PRINTER = "Printers / MFPs"
    SWITCH = "Switches / Routers"
    FIREWALL = "Firewalls"
    AP = "Wireless AP"
    CAMERA = "Cameras / IoT"
    VOIP = "VoIP Devices"
    MOBILE_IOS = "Mobile (iOS)"
    MOBILE_ANDROID = "Mobile (Android)"
    UPS = "UPS / Power"
    NAS = "NAS / Storage"
    TV = "Smart TV / Display"
    MISC = "Miscellaneous"
    UNKNOWN = "Unknown"
    NO_RESPONSE = "No response"
    ERROR = "Error"


# Categories a user can pick from in the UI (order shown in the dropdown).
CATEGORY_CHOICES = [
    Cat.WINDOWS, Cat.MAC, Cat.LINUX, Cat.SERVER_HV, Cat.SERVER, Cat.BMC,
    Cat.PRINTER, Cat.SWITCH, Cat.FIREWALL, Cat.AP, Cat.CAMERA, Cat.VOIP,
    Cat.MOBILE_IOS, Cat.MOBILE_ANDROID, Cat.UPS, Cat.NAS, Cat.TV, Cat.MISC,
]

# Categories that can actually run an EDR/VM agent. A printer or switch
# "missing Defender" is not a finding, so coverage only flags these.
AGENT_CAPABLE = {
    Cat.WINDOWS, Cat.MAC, Cat.LINUX, Cat.SERVER_HV, Cat.SERVER,
}

# Categories that mean "did not identify" - excluded from the identified count.
UNKNOWN_CATEGORIES = {Cat.UNKNOWN, Cat.MISC, Cat.NO_RESPONSE, Cat.ERROR}

# Old classifier names -> canonical names, for the 1.1 migration.
LEGACY_RENAMES = {
    "Endpoint (Windows)": Cat.WINDOWS,
    "Endpoint (Mac)": Cat.MAC,
    "Server/Hypervisor": Cat.SERVER_HV,
    "Printer": Cat.PRINTER,
    "Switch/Router": Cat.SWITCH,
    "Firewall": Cat.FIREWALL,
    "Camera/IoT": Cat.CAMERA,
    "VoIP": Cat.VOIP,
}
