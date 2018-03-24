package main

import (
	"fmt"
	"golang.org/x/sys/windows/registry"
	"log"
	"strconv"
)

func getThing(path, name, valType, des,  expected string) {
	fmt.Println("[-] Scanning: ", des)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, path , registry.QUERY_VALUE)
	if err != nil {
		log.Fatal(err)
	}
	defer k.Close()

	switch valType{
	case "String":
		s, _, err := k.GetStringValue(name)
		if err != nil {
			fmt.Println(err)
		} else if s != expected {
			fmt.Println("\t [!] Anomolay Detected [!]")
		} else {
			fmt.Println("\t [+] Protected")
		}
	case "Integer":
		s, _, err := k.GetIntegerValue(name)
		if err != nil {
			fmt.Println(err)
		}else if strconv.Itoa(int(s)) != expected {
			fmt.Println("\t [!] Anomolay Detected [!] ")
		} else {
			fmt.Println("\t [+] Protected")
		}
	}

}

func main() {
	getThing(`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, "SystemRoot", "String", "Windows Current Version", "C:\\Windows")
	getThing(`SYSTEM\CurrentControlSet\Control\Session Manager`, "CWDIllegalInDllSearch", "Integer", "DLL Search", "1")
	getThing(`SOFTWARE\Microsoft\Security Center`, "FirewallDisableNotify", "Integer", "Disabled Firewall Notification", "0")
	getThing(`SOFTWARE\Microsoft\Security Center`, "AntiVirusDisableNotify", "Integer","Disabled AntiVirus Notification", "0")
	getThing(`SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore`, "DisableDRDword", "Integer","Disabled System Restore", "0")
	getThing(`SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_WEBOC_POPUPMANAGEMENT`, "iexplore.exe", "Integer","Disabled Pop Ups", "0")


}