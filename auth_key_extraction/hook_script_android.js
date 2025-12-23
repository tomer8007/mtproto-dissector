//
// Injected to the Telegram process on Android.
//


var retriedFindingAuthKey = false;
var verbose = false;
var foundAuthKey = false;
var foundAuthKeyIDs = [];

console.log("[JS] Hello from injected JS");
hookAndroid();

function hookAndroid()
{
    console.log("[JS] Searching for Datacenter::getAuthKey...");
    var getAuthKeyAddress = findGetAuthKeyFunction();
    if (!getAuthKeyAddress)
    {
        console.log("[JS] Could not find the address of Datacenter::getAuthKey!");
        if (!retriedFindingAuthKey)
        {
            // maybe the app is not fully loaded yet
            console.log("[JS] Trying again in 5 seconds.");
            retriedFindingAuthKey = true;
            setTimeout(hookAndroid);
        }
        return;
    }
    console.log("[JS] Datacenter::getAuthKey() is at 0x" + getAuthKeyAddress.toString(16));

    console.log("[JS] attaching interceptor to Datacenter::getAuthKey() at ", getAuthKeyAddress.toString());
    Interceptor.attach(getAuthKeyAddress, 
    {
        // https://github.com/DrKLO/Telegram/blob/702d37ce69fca77e78072ad408e9d29dfd2d2be8/TMessagesProj/jni/tgnet/Datacenter.cpp#L1062
        // ByteArray *Datacenter::getAuthKey(ConnectionType connectionType, bool perm, int64_t *authKeyId, int32_t allowPendingKey) {
        onEnter: function (args) 
        {
            if (verbose)
            {
                console.log("[HOOK] Datacenter::getAuthKey was called.");
            }

            var this_ = args[0];
            var connection_type = args[1];
            var perm = args[2];
            var authKeyIdPtr = args[3];
            var allowPendingKey = args[3];

            if (authKeyIdPtr.toInt32() == 0) return;

            this.hadAuthKeyID = true;
            this.authKeyIdPtr = authKeyIdPtr;


            //console.log("[HOOK] this_ = " + this_.toString());
            //console.log("[HOOK] connection_type = " + connection_type.toString());
            //console.log("[HOOK] perm = " + perm.toString());
            //console.log("[HOOK] authKeyIdPtr = " + authKeyIdPtr.toString());
            //console.log("[HOOK] allowPendingKey = " + allowPendingKey.toString());

        },
        onLeave: function(retval)
        {
            if (this.hadAuthKeyID)
            {
                var authKeyByteArrayPtr = retval;

                var authKeyId = new Uint8Array(this.authKeyIdPtr.readByteArray(8));
                
                for (var i = 0; i < foundAuthKeyIDs.length; i++)
                {
                    if (foundAuthKeyIDs[i] == uint8ArrayToHex(authKeyId)) return; // don't spam the console
                }

                foundAuthKeyIDs.push(uint8ArrayToHex(authKeyId));

                console.log("[HOOK] leaving Datacenter::getAuthKey");
                console.log("[HOOK] Auth key ID: 0x" + uint8ArrayToHex(authKeyId));

                var length = authKeyByteArrayPtr.readU32();
                var authKeyDataPtr = authKeyByteArrayPtr.add(4).readPointer();
                var authKey = new Uint8Array(authKeyDataPtr.readByteArray(256));

                console.log("[HOOK] auth key length: " + length.toString());
                console.log("[HOOK] Auth key (2048 bits): ", uint8ArrayToHex(authKey));
            }

        }
    });


    console.log("[JS] Waiting for the auth key to appear.");
}

function findGetAuthKeyFunction() 
{
    // 1) try exact global export
    var targetFunction = "_ZN10Datacenter10getAuthKeyE14ConnectionTypebPxi"
    var foundExportAddress = findGlobalExportByName(targetFunction);
    if (foundExportAddress) 
        return foundExportAddress;

    // 2) enumerate modules and exports; match exact name or substring matches
    var modules = Process.enumerateModules();
    for (var i = 0; i < modules.length; i++) 
    {
        var m = modules[i];
        var exports = null;
        try {
            exports = Module.enumerateExports(m.name);
        } catch (e) {
            continue;
        }
        for (var j = 0; j < exports.length; j++) 
        {
            var candidateExport = exports[j];
            var name = candidateExport.name || "";
            var lower = name.toLowerCase();
            if (name === targetFunction || (lower.indexOf("datacenter") !== -1 && lower.indexOf("getauthkey") !== -1) ) 
            {
                console.log("[JS] Found candidate: " + name);
                return candidateExport.address;
            }
        }
    }
    
    return null;
}

function findGlobalExportByName(symbolName) {
    if (Module.findGlobalExportByName) {
        // Frida 17+ built-in version
        return Module.findGlobalExportByName(symbolName);
    }

    // --- Polyfill for Frida < 17 ---
    // Module.findExportByName searches normal symbols (functions + data)
    const addr = Module.findExportByName(null, symbolName);
    if (addr) return addr;

    return null;
}


function uint8ArrayToHex(u8) 
{
    var hexChars = "0123456789abcdef";
    var out = "";
    for (var i = 0; i < u8.length; i++) {
      var b = u8[i];
      out += hexChars[b >> 4] + hexChars[b & 0x0f];
    }
    return out;
}
