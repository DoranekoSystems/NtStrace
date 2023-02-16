// original software:https://github.com/sh1ma/iostrace
// Usage: frida -l tracer.js app.exe

var Color = {
  RESET: "\x1b[39;49;00m",
  Black: "0;01",
  Blue: "4;01",
  Cyan: "6;01",
  Gray: "7;11",
  Green: "2;01",
  Purple: "5;01",
  Red: "1;01",
  Yellow: "3;01",
  Light: {
    Black: "0;11",
    Blue: "4;11",
    Cyan: "6;11",
    Gray: "7;01",
    Green: "2;11",
    Purple: "5;11",
    Red: "1;11",
    Yellow: "3;11",
  },
};

var LOG = function (input, kwargs) {
  kwargs = kwargs || {};
  var logLevel = kwargs["l"] || "log",
    colorPrefix = "\x1b[3",
    colorSuffix = "m";
  if (typeof input === "object")
    input = JSON.stringify(input, null, kwargs["i"] ? 2 : null);
  if (kwargs["c"])
    input = colorPrefix + kwargs["c"] + colorSuffix + input + Color.RESET;
  console[logLevel](input);
};

var module = Process.getModuleByName("ntdll.dll");
var symbols = module.enumerateExports();

var sysDict = {};
for (var i = 0; i < symbols.length; i++) {
  const sysName = symbols[i].name;
  if (
    (sysName.indexOf("_NT") == 0 || sysName.indexOf("Nt") == 0) &&
    sysName.indexOf("Ntdll") == -1
  ) {
    const symAddr = symbols[i].address;
    const sysNumber = symAddr.add(0x04).readUInt();
    sysDict[sysNumber] = sysName;
  }
}

var ThreadsFollowed = {};

function isThreadFollowed(tid) {
  if (ThreadsFollowed[tid]) {
    return true;
  } else {
    return false;
  }
}

function onMatch(context) {
  var calledNumber = context.rax.toInt32();
  var sysName = sysDict[calledNumber];
  LOG(
    `${DebugSymbol.fromAddress(context.rip).moduleName}!${
      DebugSymbol.fromAddress(context.rip).address
    }`
  );
  LOG(`[${calledNumber}]${sysName}`, { c: Color.Green });
  if (sysName == "NtCreateThread" || sysName == "NtCreateThreadEx") {
    var funcPtr = ptr(context.rsp.add(0x28).readU64());
    Interceptor.attach(funcPtr, {
      onEnter(args) {
        if (isThreadFollowed(this.threadId)) {
          return;
        }
        FollowThread(this.threadId);
      },
      onLeave(retVal) {
        UnfollowThread(this.threadId);
      },
    });
  }
}

function FollowThread(tid) {
  if (isThreadFollowed(tid)) {
    return;
  }
  ThreadsFollowed[tid] = true;
  LOG("[+] Following thread " + tid, { c: Color.Red });
  Stalker.follow(tid, {
    transform: function (iterator) {
      const instruction = iterator.next();
      do {
        if (instruction.mnemonic === "syscall") {
          iterator.putCallout(onMatch);
        }
        iterator.keep();
      } while (iterator.next() !== null);
    },
  });
}

function UnfollowThread(threadId) {
  if (!isThreadFollowed(threadId)) {
    return;
  }
  delete ThreadsFollowed[threadId];
  LOG("[+] Unfollowing thread " + threadId, { c: Color.Red });
  Stalker.unfollow(threadId);
  Stalker.garbageCollect();
}

const ths = Process.enumerateThreads();
ths.forEach((el) => {
  FollowThread(el.id);
});
