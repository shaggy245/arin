package main

import (
    "net/http"
    "fmt"
    "log"
    "io/ioutil"
    "os"
    "errors"
    "strconv"
)

func queryPOC(c *http.Client, poc string) (string, error) {
    // Get ARIN NET cods for ARIN POC
    path := "/org/" + poc + "/nets"
    req, err := http.NewRequest("GET", "https://whois.arin.net/rest" + path, nil)
    if err != nil {
        return "", err
    }
    req.Header.Add("accept", "application/json")
    resp, err := c.Do(req)
    if err != nil {
        return "", err
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return "", err
    }
    if resp.StatusCode == 404 {
        return "", errors.New("ARIN POC not found or no networks found for " + poc)
    } else if resp.StatusCode != 200 {
        return "", errors.New("Non-200 status code received: " + strconv.Itoa(resp.StatusCode))
    }
    return string(body), nil
}

func main() {
    if len(os.Args) == 0 {
        log.Fatal("Requires one arg of ARIN WHOIS POC handle (https://www.arin.net/resources/guide/account/records/poc/)")
    }

    handle := os.Args[1]
    /*
    https://whois.arin.net/rest/org/EI-162
    "https://whois.arin.net/rest/org/<handle>"
    https://whois.arin.net/rest/net/NET-192-138-209-0-1
    "https://whois.arin.net/rest/net/<net-definition>"
    */

    client := &http.Client{}
    nets, err := queryPOC(client, handle)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(nets)
}
