# PIE-Investigation
My analysis on the picoCTF challenge, PIE TIME 2

## File Investigation
PIE Is another compiler defense that is used to defend against common exploits. This challenge we will be looking at today is called PIE TIME 2 from the picoCTF website. The challege can be found [here](https://play.picoctf.org/practice/challenge/491?page=1&search=PIE%20TIME). After downloading the files we can begin. 

Let's start by running the program in its default state.

<img width="1309" height="329" alt="image" src="https://github.com/user-attachments/assets/727ef305-b926-47b1-b538-0a96706b47ea" />


We can see the program is simple. It asks for your name, then an address to jump to. Let's run checksec on it to see the defenses it was compiled with. 

<img width="931" height="569" alt="image" src="https://github.com/user-attachments/assets/0621f50d-2d46-4a48-9047-f3628340f96e" />


So this is a binary compiled with Stack Canaries, NX Enabled, PIE, and other defenses. Let's investigate the source code `vuln.c` to see what we are actually working with. 
We can see `main()` as such:
```
int main() {
  signal(SIGSEGV, segfault_handler);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  call_functions();
  return 0;
}
```

And we can see `call_functions()` as such:
```
void call_functions() {
  char buffer[64];
  printf("Enter your name:");
  fgets(buffer, 64, stdin);
  printf(buffer);

  unsigned long val;
  printf(" enter the address to jump to, ex => 0x12345: ");
  scanf("%lx", &val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
```

Looking at `call_functions()`, we can see that this is where we are asked for our name. There's a clear format string vulnerability in the lines:
```
fgets(buffer, 64, stdin);
printf(buffer);
```

The input from the user is unchecked and is simply printed through `printf()`. We can use this format string vulnerability to leak some information from the stack. 

<img width="3780" height="331" alt="image" src="https://github.com/user-attachments/assets/a166766b-b436-4e77-a1a9-28b44219f3f4" />


I used 25 `%p` inputs for the first user prompt which resulted in a segfault, but that doesn't necessary matter. The program gives us the ability to jump to any memory address we want, so we want to jump to the address of `win()` and receive the flag. The binary was compiled with PIE as a defense. Position Independent Executable (PIE) means that exectuables are loaded into random memory addresses every runtime, making ASLR more effective against attacks like Return Oriented Programming (see my [ExecStackInvestigation](https://github.com/Jamie-R24/ExecStackInvestigation) repo for explanation on ROP). Let's investigate this by running the program multiple times, with the same input of 25 `%p`s. 

<img width="3805" height="1459" alt="image" src="https://github.com/user-attachments/assets/72e49655-8804-4865-b7d0-2ca54a14f787" />

Looking at this output, we see that the memory addresses are different for each run of the program we did. You also see a lot of `702520` and that's because this represents our `%p` in hex. For our exploit to be successful, we need to find the memory address area of our executable and then calculate the address of `win()` to pass to the program. 

First we can find the general address (last 2 bytes) of the `win()` function using gdb and checking `info functions`. 

<img width="1367" height="1693" alt="image" src="https://github.com/user-attachments/assets/88b7ff14-82d1-4b29-bca9-dc302e1c63b5" />


We see the the address is `0x136a` which is clearly not a full address. The full address is hidden from us until runtime. If we can leak a memory address value from the stack, let's say the return address of `main()`, then we can use that address and calculate the address of win. First we need to calculate the offset of the return for `main()` and `win()`. We know `win()` and we can find `main()` by running `disas main` in gdb. Then we can use gdb to perform some math on the hex values.

<img width="2482" height="1124" alt="image" src="https://github.com/user-attachments/assets/91a3ec1e-d251-4899-9c67-52ba5b83fa76" />


Now we know that `win()` is `0xd7` away from the end of `main()`. Now we need to see where that address for `main()` is located on the stack. Let's run the program in gdb, pass in the 25 `%p` and then check around the stack to see what values we can get. 

<img width="1467" height="948" alt="image" src="https://github.com/user-attachments/assets/2cdbec27-c3a9-4fa6-9cfc-ed98c30b2740" />


This address has an ending that looks awfully familiar...We can confirm that this is `main()`. Running `./vuln` then passing in the 25 `%p`s again, we can see that this value appears 19th off the stack. 

<img width="3777" height="317" alt="image" src="https://github.com/user-attachments/assets/97b25482-80c9-4bab-bd56-426a49f55121" />


We can use `%19$p` in the first input to leak that value. Once, we leak that value, we can subtract the offset we determined of `0xd7` from it and we should get our address for `win()`. Let's try. 

<img width="1115" height="288" alt="image" src="https://github.com/user-attachments/assets/02912942-3212-427b-adba-ac8b2d10ff08" />

<img width="780" height="168" alt="image" src="https://github.com/user-attachments/assets/c7870de5-c579-44a7-a452-0fb0dc5d6854" />

<img width="1388" height="340" alt="image" src="https://github.com/user-attachments/assets/9bc31da4-5b00-4980-9958-b36307c02a9c" />

And just like that we get the flag. No python script is really needed for this to automate the exploitation. Using the command given by the challenge, you can connect to the server, leak the address with `%19$p` then use a hex calculator or gdb to subtract `0xd7` from it and determine the actual address to input. 

Hope this made sense and best of luck

