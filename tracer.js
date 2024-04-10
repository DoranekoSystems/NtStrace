// original software:https://github.com/sh1ma/iostrace
// Usage: frida -l tracer.js app.exe

var color = {
  reset: '\x1b[39;49;00m',
  black: '0;01',
  blue: '4;01',
  cyan: '6;01',
  gray: '7;11',
  green: '2;01',
  purple: '5;01',
  red: '1;01',
  yellow: '3;01',
  light: {
    black: '0;11',
    blue: '4;11',
    cyan: '6;11',
    gray: '7;01',
    green: '2;11',
    purple: '5;11',
    red: '1;11',
    yellow: '3;11',
  },
};

var log = function (input, kwargs) {
  kwargs = kwargs || {};
  var logLevel = kwargs['l'] || 'log',
    colorPrefix = '\x1b[3',
    colorSuffix = 'm';
  if (typeof input === 'object') input = JSON.stringify(input, null, kwargs['i'] ? 2 : null);
  if (kwargs['c']) input = colorPrefix + kwargs['c'] + colorSuffix + input + color.reset;
  console[logLevel](input);
};

var module = Process.getModuleByName('ntdll.dll');
var symbols = module.enumerateExports();
var sysDict = {};
var sysAddressList = [];
var threadStepsDict = {};
var threadsFollowed = {};

for (var i = 0; i < symbols.length; i++) {
  const sysName = symbols[i].name;
  if (
    (sysName.indexOf('_NT') == 0 || sysName.indexOf('Nt') == 0) &&
    sysName.indexOf('Ntdll') == -1
  ) {
    const symAddr = symbols[i].address;
    const sysNumber = symAddr.add(0x04).readUInt();
    sysDict[sysNumber] = sysName;
    sysAddressList.push(parseInt(symAddr));
  }
}

function isThreadFollowed(tid) {
  if (threadsFollowed[tid]) {
    return true;
  } else {
    return false;
  }
}

function onMatch(context) {
  var threadId = Process.getCurrentThreadId();
  var threadSteps = threadStepsDict[threadId];

  // ignore frida's thread
  if (parseInt(context.rip) + 2 != threadSteps[0]) {
    return;
  }

  var calledNumber = context.rax.toInt32();
  var sysName = sysDict[calledNumber];
  log(
    `${DebugSymbol.fromAddress(context.rip).moduleName}!${
      DebugSymbol.fromAddress(context.rip).address
    }`
  );
  var inNtDllFlag = false;
  if (sysAddressList.indexOf(threadSteps[5]) != -1) {
    inNtDllFlag = true;
  }
  if (inNtDllFlag) {
    log(`[${calledNumber}]${sysName}`, { c: color.green });
  } else {
    log(`[${calledNumber}]${sysName}`, { c: color.blue });
  }
  if (sysName == 'NtCreateThread' || sysName == 'NtCreateThreadEx') {
    var funcPtr = ptr(context.rsp.add(0x28).readU64());
    Interceptor.attach(funcPtr, {
      onEnter(args) {
        if (isThreadFollowed(this.threadId)) {
          return;
        }
        followThread(this.threadId);
      },
      onLeave(retVal) {
        unfollowThread(this.threadId);
      },
    });
  }
}

function followThread(tid) {
  if (isThreadFollowed(tid)) {
    return;
  }
  threadsFollowed[tid] = true;
  log('[+] Following thread ' + tid, { c: color.red });
  Stalker.follow(tid, {
    transform: function (iterator) {
      const instruction = iterator.next();
      do {
        var threadId = Process.getCurrentThreadId();
        if (threadStepsDict[threadId] == undefined) {
          threadStepsDict[threadId] = [0, 0, 0, 0, 0, 0];
        }
        threadStepsDict[threadId].unshift(parseInt(instruction.address));
        threadStepsDict[threadId].pop();
        if (instruction.mnemonic === 'syscall') {
          iterator.putCallout(onMatch);
        }
        iterator.keep();
      } while (iterator.next() !== null);
    },
  });
}

function unfollowThread(threadId) {
  if (!isThreadFollowed(threadId)) {
    return;
  }
  delete threadsFollowed[threadId];
  log('[+] Unfollowing thread ' + threadId, { c: color.red });
  Stalker.unfollow(threadId);
  Stalker.garbageCollect();
}

const ths = Process.enumerateThreads();
ths.forEach((el) => {
  followThread(el.id);
});
