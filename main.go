package main

import (
    "net/http"
    "fmt"
    "log"
    "io/ioutil"
    "os"
    "errors"
    "strconv"
    "encoding/json"
)

func queryPOC(c *http.Client, poc string) ([]string, error) {
    // Get ARIN NET cods for ARIN POC
    path := "/org/" + poc + "/nets"
    req, err := http.NewRequest("GET", "https://whois.arin.net/rest" + path, nil)
    if err != nil {
        return nil, err
    }
    req.Header.Add("accept", "application/json")
    resp, err := c.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    body, err := ioutil.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    if resp.StatusCode == 404 {
        return nil, errors.New("ARIN POC not found or no networks found for " + poc)
    } else if resp.StatusCode != 200 {
        return nil, errors.New("Non-200 status code received: " + strconv.Itoa(resp.StatusCode))
    }

    nets, err := extractPOCNets(body)
    if err != nil {
        return nil, err
    }
    return nets, nil
}

func extractPOCNets(body []byte) ([]string, error) {
    argnets := make(map[string]map[string]interface{})
    err := json.Unmarshal(body, &argnets)
    if err != nil {
        return nil, err
    }
    nets := make([]string, 1)
    //netrefs can be a single map or an array of maps
    switch netrefs := argnets["nets"]["netRef"].(type) {
    case map[string]interface{}:
	nets[0] = netrefs["@handle"].(string)
    case []interface{}:
        nets = make([]string, len(netrefs))
	for i := 0; i < len(netrefs); i++ {
	    netref := netrefs[i].(map[string]interface{})
	    nets[i] = netref["@handle"].(string)
	}
    default:
        return nil, errors.New("Unknown netRef var type in json response")
    }
    return nets, nil
}

func queryNets(c *http.Client, netrefs []string) ([]string, error) {
    return nil, nil
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
