# Entry Point Injection
This is a re-implementation of [Kudaes's](https://github.com/Kudaes) threadless process injection through entry point hijacking in C. It is higly advised that you go over the [original technique](https://github.com/Kudaes/EPI) as it contains a more in depth explanation of the technique.

This solution is comprised of two parts:
  - ```EntryPointInjection.exe```: Responsible for injecting the loader and patching the PEB, pointing one of the process' loaded dll's entry point to the injected shellcode.
  - ```Loader.dll```: Responsible for restoring the PEB to it's original state and executing the main payload (calc.exe shellcode in the provided example). ```Loader.dll``` will need to be converted to sRDI and injected.

## Usage 
To convert your Loader.dll to sRDI, use the provided python script:
````
python ConvertToShellcode.py -of <raw/string> Loader.dll
````
This example stores the shellcode (unecrypted) in the .rsrc section.

To inject to a remote process, simply specify the target process' name:
````
.\EntryPointInjection.exe notepad.exe
````
## Example 
In the following example our shellcode is injected in to ```chrome.exe``` and executed once a thread is created in the process:

![epi](https://github.com/kr0tt/EntryPointInjection/assets/106829987/212b6efe-a197-4eb9-991c-e1e59fe998bc)

## Credits
- [Kudaes](https://github.com/Kudaes) for this awesome technique.
- [NUL0x4C](https://github.com/NUL0x4C) and [mrd0x](https://github.com/mrd0x) for [Maldev Academy](https://maldevacademy.com/), thank you for this amazing platform.
