// SPDX-License-Identifier: Apache-2.0
/* Copyright Martynas Pumputis */
/* Copyright Authors of Cilium */

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	pb "github.com/cheggaaa/pb/v3"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	"github.com/cilium/pwru/internal/libpcap"
	"github.com/cilium/pwru/internal/pwru"
)

func main() {
	flags := pwru.Flags{}
	flags.SetFlags()
	flags.Parse()

	if flags.ShowVersion {
		fmt.Printf("pwru %s\n", pwru.Version)
		os.Exit(0)
	}

	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{
		Cur: 8192,
		Max: 8192,
	}); err != nil {
		log.Fatalf("failed to set temporary rlimit: %s", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to set temporary rlimit: %s", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var btfSpec *btf.Spec
	var err error
	// 加载内核的BTF文件的信息，即：vmlinux，包含了内核中所有的函数、结构体的定义
	if flags.KernelBTF != "" {
		btfSpec, err = btf.LoadSpec(flags.KernelBTF)
	} else {
		btfSpec, err = btf.LoadKernelSpec()
	}
	if err != nil {
		log.Fatalf("Failed to load BTF spec: %s", err)
	}

	if flags.AllKMods {
		// /sys/kernel/btf 这个目录下包含有所有模块的BTF信息，每一个BTF文件包含了该模块中的函数以及结构体定义
		files, err := os.ReadDir("/sys/kernel/btf")
		if err != nil {
			log.Fatalf("Failed to read directory: %s", err)
		}

		flags.KMods = nil
		for _, file := range files {
			if !file.IsDir() && file.Name() != "vmlinux" {
				flags.KMods = append(flags.KMods, file.Name())
			}
		}
	}

	var useKprobeMulti bool
	if flags.Backend != "" && (flags.Backend != pwru.BackendKprobe && flags.Backend != pwru.BackendKprobeMulti) {
		log.Fatalf("Invalid tracing backend %s", flags.Backend)
	}
	// Until https://lore.kernel.org/bpf/20221025134148.3300700-1-jolsa@kernel.org/
	// has been backported to the stable, kprobe-multi cannot be used when attaching
	// to kmods.
	if flags.Backend == "" && len(flags.KMods) == 0 {
		// 通过实际使用BackendKprobeMulti是否报错来判断是否支持BackendKprobeMulti
		useKprobeMulti = pwru.HaveBPFLinkKprobeMulti()
	} else if flags.Backend == pwru.BackendKprobeMulti {
		useKprobeMulti = true
	}
	// 遍历内核以及所有模块中所有和sk_buf相关的函数(参数中包含有sk_buf)
	// 另外函数必须匹配flags.FilterFunc 而且函数支持KProbe
	// 而KProbe是有白名单的，其支持的信息包含在/sys/kernel/debug/tracing/available_filter_functions中
	funcs, err := pwru.GetFuncs(flags.FilterFunc, btfSpec, flags.KMods, useKprobeMulti)
	if err != nil {
		log.Fatalf("Failed to get skb-accepting functions: %s", err)
	}
	if len(funcs) <= 0 {
		log.Fatalf("Cannot find a matching kernel function")
	}
	// 获取内核中函数的地址信息，内核中所有函数的地址信息包含在/proc/kallsyms中
	// 为了支持输入函数的调用栈，需要函数地址到函数名的调用关系都保存下来，并按地址排序
	// 另外若一个地址>第N个函数的起始地址，小于第N+1个函数的起始地址，则认为该地址是输入第N个函数中。
	// If --filter-trace-tc, it's to retrieve and print bpf prog's name.
	addr2name, err := pwru.GetAddrs(funcs, flags.OutputStack ||
		len(flags.KMods) != 0 || flags.FilterTraceTc)
	if err != nil {
		log.Fatalf("Failed to get function addrs: %s", err)
	}

	var opts ebpf.CollectionOptions
	opts.Programs.KernelTypes = btfSpec
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = ebpf.DefaultVerifierLogSize * 100

	// 这些函数都是通过github.com/cilium/ebpf/cmd/bpf2go 工具生成的
	// 这个工具主要是根据C文件生成BTF，然后生成一些Go函数，方便加载以及Attach BTF到相关的Hook点
	var bpfSpec *ebpf.CollectionSpec
	switch {
	case flags.OutputSkb && useKprobeMulti:
		bpfSpec, err = LoadKProbeMultiPWRU()
	case flags.OutputSkb:
		bpfSpec, err = LoadKProbePWRU()
	case useKprobeMulti:
		bpfSpec, err = LoadKProbeMultiPWRUWithoutOutputSKB()
	default:
		bpfSpec, err = LoadKProbePWRUWithoutOutputSKB()
	}
	if err != nil {
		log.Fatalf("Failed to load bpf spec: %v", err)
	}

	for name, program := range bpfSpec.Programs {
		// Skip the skb-tracking ones that should not inject pcap-filter.
		if name == "kprobe_skb_lifetime_termination" ||
			name == "fexit_skb_clone" ||
			name == "fexit_skb_copy" {
			continue
		}
		// 用户是直接可以在程序启动的时候，以Pcap语法格式指定数据包的过滤规则的，比如: "tcp dst 1.1.1.1"
		// 所以这里需要将用户的过滤规则编译成eBPF，注入到eBPF的BTF中
		// 从而做到再重新编译文件的情况下修改过滤规则
		if err = libpcap.InjectFilters(program, flags.FilterPcap); err != nil {
			log.Fatalf("Failed to inject filter ebpf for %s: %v", name, err)
		}
	}

	pwruConfig, err := pwru.GetConfig(&flags)
	if err != nil {
		log.Fatalf("Failed to get pwru config: %v", err)
	}
	// 这里在加载BTF到内核前，改写BTF中的常量的值
	// 配置信息实际上是可以直接通过Map传递的，如果通过Map来实现配置，则每次查询配置信息的时候，都需要一次Map查询，性能不够高
	// 通过常量，编译器生成的代码直接检测对应的常量即可
	if err := bpfSpec.RewriteConstants(map[string]interface{}{
		"CFG": pwruConfig,
	}); err != nil {
		log.Fatalf("Failed to rewrite config: %v", err)
	}

	// As we know, for every fentry tracing program, there is a corresponding
	// bpf prog spec with attaching target and attaching function. So, we can
	// just copy the spec and keep the fentry_tc program spec only in the copied
	// spec.
	// 有些机器上包含有TC/Classfier相关的BPF程序，这些BPF程序也会处理sk_buf
	// 我们要做的是跟踪数据包在各个内核函数中的调用情况。这些BTF程序也需要被考虑到。
	bpfSpecFentry := bpfSpec.Copy()
	bpfSpecFentry.Programs = map[string]*ebpf.ProgramSpec{
		"fentry_tc": bpfSpec.Programs["fentry_tc"],
	}

	// fentry_tc is not used in the kprobe/kprobe-multi cases. So, it should be
	// deleted from the spec.
	delete(bpfSpec.Programs, "fentry_tc")

	// If not tracking skb, deleting the skb-tracking programs to reduce loading
	// time.
	if !flags.FilterTrackSkb {
		delete(bpfSpec.Programs, "kprobe_skb_lifetime_termination")
	}

	// 我们需要跟踪数据包的全生命周期，由于数据包在内核处理过程中其地址或端口信息可能会发生变化
	// 有可能刚开始数据包满足PCap规则，但是在内核传递过程中，数据发生了变化，导致不满足Pcap规则，而这个包也是需要被跟踪的。
	// 这种场景下，skb的地址是没有变的，所以通过一个Map来跟踪感兴趣的skb的地址，如果该skb的地址存在于Map中，则也需要跟踪。
	// 但是内核在一些场景下，会拷贝skb，导致skb的地址发生变化，从而导致跟踪丢失了。
	// 所以需要在调用拷贝函数之后，拿到拷贝函数的返回值(其中包含了新skb的地址)，让新skb的地址放到Map中。
	// 这里判断机器是否支持AttachTraceFExit类型
	haveFexit := pwru.HaveBPFLinkTracing()
	if !flags.FilterTrackSkb || !haveFexit {
		delete(bpfSpec.Programs, "fexit_skb_clone")
		delete(bpfSpec.Programs, "fexit_skb_copy")
	}

	coll, err := ebpf.NewCollectionWithOptions(bpfSpec, opts)
	if err != nil {
		var (
			ve          *ebpf.VerifierError
			verifierLog string
		)
		if errors.As(err, &ve) {
			verifierLog = fmt.Sprintf("Verifier error: %+v\n", ve)
		}

		log.Fatalf("Failed to load objects: %s\n%+v", verifierLog, err)
	}
	defer coll.Close()
	// 内核中处理skb的函数，有些是第一个参数是skb，有些是第2个，针对skb参数所处的位置不同，需要定义不同的KProbe函数来处理
	kprobe1 := coll.Programs["kprobe_skb_1"]
	kprobe2 := coll.Programs["kprobe_skb_2"]
	kprobe3 := coll.Programs["kprobe_skb_3"]
	kprobe4 := coll.Programs["kprobe_skb_4"]
	kprobe5 := coll.Programs["kprobe_skb_5"]
	// 拿到BTF中相关的Map
	events := coll.Maps["events"]
	printStackMap := coll.Maps["print_stack_map"]
	printSkbMap := coll.Maps["print_skb_map"]
	// 对于机器上加载ebpf，也需要做KProbe
	if flags.FilterTraceTc {
		close, err := pwru.TraceTC(coll, bpfSpecFentry, &opts, flags.OutputSkb)
		if err != nil {
			log.Fatalf("Failed to trace TC: %v", err)
		}
		defer close()
	}

	var kprobes []link.Link
	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Detaching kprobes...")
			bar := pb.StartNew(len(kprobes))
			for _, kp := range kprobes {
				_ = kp.Close()
				bar.Increment()
			}
			bar.Finish()

		default:
			for _, kp := range kprobes {
				_ = kp.Close()
			}
		}
	}()

	msg := "kprobe"
	if useKprobeMulti {
		msg = "kprobe-multi"
	}
	log.Printf("Attaching kprobes (via %s)...\n", msg)
	ignored := 0
	bar := pb.StartNew(len(funcs))

	if flags.FilterTrackSkb {
		// skb 内存释放后，就从Map中删除skb的地址信息，避免占用过多的内存
		kp, err := link.Kprobe("kfree_skbmem", coll.Programs["kprobe_skb_lifetime_termination"], nil)
		bar.Increment()
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				log.Fatalf("Opening kprobe kfree_skbmem: %s\n", err)
			} else {
				ignored += 1
				log.Printf("Warn: kfree_skbmem not found, pwru is likely to mismatch skb due to lack of skb lifetime management\n")
			}
		} else {
			kprobes = append(kprobes, kp)
		}

		if haveFexit {
			// 跟中skb的复制场景，将新地址加入到Map中，以后该地址的skb都会被跟踪。
			progs := []*ebpf.Program{
				coll.Programs["fexit_skb_clone"],
				coll.Programs["fexit_skb_copy"],
			}
			for _, prog := range progs {
				fexit, err := link.AttachTracing(link.TracingOptions{
					Program: prog,
				})
				bar.Increment()
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						log.Fatalf("Opening tracing(%s): %s\n", prog, err)
					} else {
						ignored += 1
					}
				} else {
					kprobes = append(kprobes, fexit)
				}
			}
		}
	}
	funcsByPos := pwru.GetFuncsByPos(funcs
	// pos代表skb参数处于函数的第几个参数
	for pos, fns := range funcsByPos {
		var fn *ebpf.Program
		switch pos {
		case 1:
			fn = kprobe1
		case 2:
			fn = kprobe2
		case 3:
			fn = kprobe3
		case 4:
			fn = kprobe4
		case 5:
			fn = kprobe5
		default:
			ignored += 1
			continue
		}

		if !useKprobeMulti {
			for _, name := range fns {
				select {
				case <-ctx.Done():
					bar.Finish()
					return
				default:
				}

				kp, err := link.Kprobe(name, fn, nil)
				bar.Increment()
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						log.Fatalf("Opening kprobe %s: %s\n", name, err)
					} else {
						ignored += 1
					}
				} else {
					kprobes = append(kprobes, kp)
				}
			}
		} else {
			select {
			case <-ctx.Done():
				bar.Finish()
				return
			default:
			}

			opts := link.KprobeMultiOptions{Symbols: funcsByPos[pos]}
			kp, err := link.KprobeMulti(fn, opts)
			bar.Add(len(fns))
			if err != nil {
				log.Fatalf("Opening kprobe-multi for pos %d: %s\n", pos, err)
			}
			kprobes = append(kprobes, kp)
		}
	}
	bar.Finish()
	log.Printf("Attached (ignored %d)\n", ignored)

	log.Println("Listening for events..")

	if flags.ReadyFile != "" {
		file, err := os.Create(flags.ReadyFile)
		if err != nil {
			log.Fatalf("Failed to create ready file: %s", err)
		}
		file.Close()
	}

	output, err := pwru.NewOutput(&flags, printSkbMap, printStackMap, addr2name, useKprobeMulti, btfSpec)
	if err != nil {
		log.Fatalf("Failed to create outputer: %s", err)
	}
	output.PrintHeader()

	defer func() {
		select {
		case <-ctx.Done():
			log.Println("Received signal, exiting program..")
		default:
			log.Printf("Printed %d events, exiting program..\n", flags.OutputLimitLines)
		}
	}()

	var event pwru.Event
	runForever := flags.OutputLimitLines == 0
	for i := flags.OutputLimitLines; i > 0 || runForever; i-- {
		for {
			// 拿到内核的数据打印出来
			if err := events.LookupAndDelete(nil, &event); err == nil {
				break
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Microsecond):
				continue
			}
		}

		output.Print(&event)

		select {
		case <-ctx.Done():
			return
		default:
		}
	}
}
