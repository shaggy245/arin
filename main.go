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

func queryARIN(c *http.Client, path string) ([]byte, error) {
    // Get ARIN cods
    req, err := http.NewRequest("GET", "https://whois.arin.net" + path, nil)
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
        return nil, errors.New("ARIN resource not found: " + path)
    } else if resp.StatusCode != 200 {
        return nil, errors.New("Non-200 status code received: " + strconv.Itoa(resp.StatusCode))
    }

    return body, nil
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

func extractCIDR(body []byte) ([]string, error) {
    argnets := make(map[string]map[string]interface{})
    err := json.Unmarshal(body, &argnets)
    if err != nil {
        return nil, err
    }
    nets := make([]string, 1)
    //netblocks can be a single map or an array of maps
    switch netblocks := argnets["net"]["netBlocks"].(map[string]interface{})["netBlock"].(type) {
    case map[string]interface{}:
        startAddr := netblocks["startAddress"].(map[string]interface{})["$"].(string)
        cidr := netblocks["cidrLength"].(map[string]interface{})["$"].(string)
	nets[0] = startAddr + "/" + cidr
    case []interface{}:
        nets = make([]string, len(netblocks))
	for i := 0; i < len(netblocks); i++ {
	    netblock := netblocks[i].(map[string]interface{})
            startAddr := netblock["startAddress"].(map[string]interface{})["$"].(string)
            cidr := netblock["cidrLength"].(map[string]interface{})["$"].(string)
	    nets[i] = startAddr + "/" + cidr
	}
    default:
        return nil, errors.New("Unknown netBlock var type in json response")
    }
    return nets, nil
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
    pathPOC := "/rest/org/" + handle + "/nets"
    pocBody, err := queryARIN(client, pathPOC)
    if err != nil {
        log.Fatal(err)
    }
    nets, err := extractPOCNets(pocBody)
    if err != nil {
        log.Fatal(err)
    }

    netCIDRs := make([]string, 0)
    for i := 0; i < len(nets); i++ {
        cidrBody, err := queryARIN(client, "/rest/net/" + nets[i])
        if err != nil {
            log.Fatal(err)
        }
        netCIDR, err := extractCIDR(cidrBody)
        if err != nil {
            log.Fatal(err)
        }
        netCIDRs = append(netCIDRs, netCIDR...)
    }
    jsonNetCIDRs, err := json.Marshal(netCIDRs)
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(string(jsonNetCIDRs))
}
