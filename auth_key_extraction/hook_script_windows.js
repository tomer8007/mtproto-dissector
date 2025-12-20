//
// Injected by frida_telegram_hook.py to the Telegram process.
//

const MODULE_NAME = "Telegram.exe";   // hardcoded module to scan

// pattern to find AuthKey::prepareAES
//.text:030983ED 0F 10 46 18             movups  xmm0, xmmword ptr [esi+18h]
// .text:030983F1 6A 34                   push    34h
const PREPARE_AES_PATTERN = "0F 10 46 18 6A 34"; //  (Frida Memory.scan format)

// pattern to find SessionPrivate::handleOneReceived
// 0000000141DFB0EC 3D A1 CF 72 30                cmp     eax, 3072CFA1h
const HANDLE_ONE_RECEIVED_PATTERN = "3D A1 CF 72 30";


const SHOULD_HOOK_APPLY_AUTH_KEY = true;

// pattern to find SessionPrivate::applyAuthKey     (it's useful to find newly estbliahsed auth keys)
//.text:028AE062 8B B3 20 03 00 00       mov     esi, [ebx+320h]
// .text:028AE068 89 83 1C 03 00 00       mov     [ebx+31Ch], eax
// .text:028AE06E 89 8B 20 03 00 00       mov     [ebx+320h]
const APPLY_AUTH_KEY_PATTERN_32 = "8B B3 20 03 00 00   89 83 1C 03 00 00   89 8B 20 03 00 00"; // (Frida Memory.scan format)
//.text:0000000141E03E2D 49 8B 96 48 04 00 00          mov     rdx, [r14+448h]
//.text:0000000141E03E34 48 85 D2                      test    rdx
const APPLY_AUTH_KEY_PATTERN_64 = "49 8B 96 48 04 00 00   48 85 D2";

var foundAuthKeyIDs = [];

console.log("[JS] Hello from injected JS");
hookWindows();

function hookWindows()
{
    
    if (Process.pointerSize == 4)
    {
        // 32 bit
        hookPrepareAesFunction();
    }
    else
    {
        // in 64 bit, prepareAES seems inlined, so hook another function
        hookHandleOneReceived();
    }


    if (SHOULD_HOOK_APPLY_AUTH_KEY)
    {
        hookApplyAuthKeyFunction();
    }

    console.log("[JS] Waiting for the auth key to appear.");
}

function hookPrepareAesFunction()
{
    var prepareAesAddr = findX86FunctionAddressByPattern(MODULE_NAME, PREPARE_AES_PATTERN);
    if (!prepareAesAddr)
    {
        console.log("[JS] Can't find AuthKey::prepareAES(). Aborting.");
        return;
    }
    console.log("[JS] AuthKey::prepareAES() is at 0x" + prepareAesAddr.toString(16));

    console.log("[JS] attaching interceptor to AuthKey::prepareAES() at ", prepareAesAddr.toString());
    Interceptor.attach(prepareAesAddr, 
    {
        // https://github.com/telegramdesktop/tdesktop/blob/02084be58399076c530de734b9d723f036652f50/Telegram/SourceFiles/mtproto/mtproto_auth_key.cpp#L78
        // void AuthKey::prepareAES(const MTPint128 &msgKey, MTPint256 &aesKey, MTPint256 &aesIV, bool send) const {
        onEnter: function (args) 
        {
            //console.log("[HOOK] -------------------------");
            //console.log("[HOOK] prepareAES was called.");

            const thisPtr = Process.pointerSize == 4 ? this.context.ecx : args[0];
            if (thisPtr.toInt32() == 0) return;

            //console.log("[HOOK] authKey pointer = ", thisPtr);

            var authKeyPointer = thisPtr;

            printAuthKey(authKeyPointer);
        },
    });
}

function hookHandleOneReceived()
{
    var handleOneAddress = findX86FunctionAddressByPattern(MODULE_NAME, HANDLE_ONE_RECEIVED_PATTERN);
    if (!handleOneAddress)
    {
        console.log("[JS] Can't find SessionPrivate::handleOneReceived(). Aborting.");
        return;
    }
    console.log("[JS] SessionPrivate::handleOneReceived() is at 0x" + handleOneAddress.toString(16));

    console.log("[JS] attaching interceptor to SessionPrivate::handleOneReceived() at ", handleOneAddress.toString());
    Interceptor.attach(handleOneAddress, 
    {
        // https://github.com/telegramdesktop/tdesktop/blob/147439ad34f6ec615c7b8c229f949c0439321221/Telegram/SourceFiles/mtproto/session_private.cpp#L1449
        // SessionPrivate::HandleResult SessionPrivate::handleOneReceived(const mtpPrime *from, const mtpPrime *end, uint64 msgId, OuterInfo info)
        onEnter: function (args) 
        {
            //console.log("[HOOK] -------------------------");
            //console.log("[HOOK] handleOneReceived was called.");
            
            var thisPtr = Process.pointerSize == 4 ? this.context.ecx : args[0];
            if (thisPtr.toInt32() == 0) return;

            //console.log("[HOOK] authKey pointer = ", thisPtr);

            // https://github.com/telegramdesktop/tdesktop/blob/d35d425918d2bd2b524c865f165f10ad7056a76c/Telegram/SourceFiles/mtproto/session_private.h#L221
            const ENCRYPTION_KEY_OFFSET_IN_SESSION_PRIVATE = 1096;

            var authKeyPointerPtr = ptr(thisPtr).add(ENCRYPTION_KEY_OFFSET_IN_SESSION_PRIVATE);
            // TODO: check that auth key looks valid

            var authKeyPointer = authKeyPointerPtr.readPointer();

            printAuthKey(authKeyPointer);
        },
    });
}

function hookApplyAuthKeyFunction()
{
    var applyAuthKeyAddr = findX86FunctionAddressByPattern(MODULE_NAME, Process.pointerSize == 4 ? APPLY_AUTH_KEY_PATTERN_32 : APPLY_AUTH_KEY_PATTERN_64);
    if (!applyAuthKeyAddr)
    {
            console.log("[JS] Can't find SessionPrivate::applyAuthKey(). Aborting.");
            return;
    }

    console.log("[JS] SessionPrivate::applyAuthKey() is at 0x" + applyAuthKeyAddr.toString(16));

    console.log("[JS] attaching interceptor to SessionPrivate::applyAuthKey() at ", applyAuthKeyAddr.toString());
    Interceptor.attach(applyAuthKeyAddr, 
    {
        // https://github.com/telegramdesktop/tdesktop/blob/147439ad34f6ec615c7b8c229f949c0439321221/Telegram/SourceFiles/mtproto/session_private.cpp#L2420
        // void SessionPrivate::applyAuthKey(AuthKeyPtr &&encryptionKey)
        onEnter: function (args) 
        {                
            var encryption_key_shared_ptr = Process.pointerSize == 4 ? args[0] : args[1]; 

            //console.log("[HOOK] -------------------------");
            //console.log("[HOOK] SessionPrivate::applyAuthKey was called.");

            if (encryption_key_shared_ptr.toInt32() == 0) return;

            var auth_key_ptr = encryption_key_shared_ptr.readPointer();
            if (auth_key_ptr.toInt32() == 0) return;

            printAuthKey(auth_key_ptr);

        },
    });
}


function printAuthKey(authKeyPointer)
{
    var keyType = authKeyPointer.readU32();
    var dcId = authKeyPointer.add(4).readU32();
    var authKey = new Uint8Array(authKeyPointer.add(8).readByteArray(256));
    var authKeyId = new Uint8Array(authKeyPointer.add(8 + 256).readByteArray(8));

    // check if we already know this auth key
    for (var i = 0; i < foundAuthKeyIDs.length; i++)
    {
        if (foundAuthKeyIDs[i] == uint8ArrayToHex(authKeyId)) return; // don't spam the console
    }

    foundAuthKeyIDs.push(uint8ArrayToHex(authKeyId));

    console.log("[HOOK] -------------------------");
    console.log("[HOOK] Key type: ", keyType);
    console.log("[HOOK] DC id: ", dcId);
    console.log("[HOOK] Auth key (2048 bits): ", uint8ArrayToHex(authKey));
    console.log("[HOOK] Auth key id: ", uint8ArrayToHex(authKeyId));
    console.log("[HOOK] -------------------------");
    console.log();
}

function findX86FunctionAddressByPattern(moduleName, pattern)
{
     // Attempt to scan executable ranges belonging to the module for speed
     var ranges = Process.enumerateRanges({ protection: 'r-x', coalesce: true });
     var patternAddr = null;
     console.log("[JS] scanning exec ranges for pattern:", pattern);
 
     for (var i = 0; i < ranges.length; i++) 
     {
         var range = ranges[i];
 
         // only scan ranges that mention the module name in r.file
         if (range.file && range.file.indexOf(moduleName) === -1) {
             continue;
         }
 
         var results = Memory.scanSync(range.base, range.size, pattern);
         if (results.length > 0) 
         {
             patternAddr = parseInt(results[0]["address"], 16);
             break;
         }
     }
 
     if (!patternAddr) {
         console.log("[JS] no pattern match found;");
         return null;
     }
 
     console.log("[JS] found pattern at 0x" + patternAddr.toString(16));
 
     var funcStart = null;
     if (Process.pointerSize == 4)
     {
        // 32 bit x86
        funcStart = findX86FunctionStart(new NativePointer(patternAddr));
     }
     else
     {
        // 64 bit x64
        funcStart = findX64FunctionStart1(new NativePointer(patternAddr));
     }
     return funcStart;
}

function findX64FunctionStart1(startAddr)
{
    // look for
    //  48 89 5C 24 10                mov     [rsp+10h], rbx
    var candidate = null;
    const loosenMax = 256;
    for (var off = 0; off <= loosenMax; off++) 
    {
        const addr = startAddr.sub(off);
        const b = addr.readU8();
        if (b === 0x48) { // push ebp
            const peek = new Uint8Array(addr.add(1).readByteArray(4));
            if (peek && ((peek[0] === 0x89 && peek[1] === 0x5C) &&
                            (peek[2] === 0x24 && peek[3] === 0x10))) {
                candidate = addr;
                console.log("[JS] function starts at", addr, "bytes:", [0x48, peek[0], peek[1]].map(function(x) { return x.toString(16)}).join(" "));
                break;
            }
        }
    }

    // look for
    // 48 8B C4                      mov     rax, rsp
    for (var off = 0; off <= loosenMax; off++) 
    {
        const addr = startAddr.sub(off);
        const b = addr.readU8();
        if (b === 0x48) { // push ebp
            const peek = new Uint8Array(addr.add(1).readByteArray(4));
            if (peek && ((peek[0] === 0x8B && peek[1] === 0xC4))) {
                candidate = addr;
                console.log("[JS] function starts at", addr, "bytes:", [0x48, peek[0], peek[1]].map(function(x) { return x.toString(16)}).join(" "));
                break;
            }
        }
    }

    if (!candidate) {
        console.log("[findX64FunctionStart1] no function start found");
        return null;
    }

    return candidate;
}

// Heuristic backward search for x86 function start (prologue) from a given match address.
// Usage: var funcStart = findX86FunctionStart(startAddr);
//   - startAddr: NativePointer (address where pattern was matched)
// Returns: NativePointer to suspected function start, or null if none found.
function findX86FunctionStart(startAddr) 
{
    // Loose fallback: search for push ebp + mov ebp, esp
    var candidate = null;
    // trying 'push ebp' search
    const loosenMax = 256;
    for (var off = 0; off <= loosenMax; off++) 
    {
        const addr = startAddr.sub(off);
        const b = addr.readU8();
        if (b === 0x55) { // push ebp
            const peek = new Uint8Array(addr.add(1).readByteArray(2));
            if (peek && ((peek[0] === 0x8B && peek[1] === 0xEC) ||
                            (peek[0] === 0x89 && peek[1] === 0xE5))) {
                candidate = addr;
                console.log("[JS] function starts at", addr,
                    "bytes:", [0x55, peek[0], peek[1]].map(function(x) { return x.toString(16)}).join(" "));
                break;
            }
        }
    }

    if (!candidate) {
        console.log("[findX86FunctionStart] no function start found");
        return null;
    }

    return candidate;
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