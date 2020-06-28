package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"runtime/debug"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/eci"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/vpc"
)

const (
	secret = ""

	ak       = ""
	sk       = ""
	regionID = ""

	zoneID          = ""
	securityGroupID = ""
	vSwitchID       = ""
)

type reqStruct struct {
	Header struct {
		Action    string `json:"action"`
		Timestamp int64  `json:"timestamp"`
		Token     string `json:"token"`
	} `json:"header"`
	Payload struct {
		Pwd  string `json:"pwd"`
		Port int64  `json:"port"`
	} `json:"payload"`
}

type respStruct struct {
	Header struct {
		Action string `json:"action"`
		Error  string `json:"error,omitempty"`
	} `json:"header"`
	Payload struct {
		IP string `json:"ip,omitempty"`
	} `json:"payload"`
}

var vpcClient *vpc.Client
var eciClient *eci.Client

func init() {
	var err error
	vpcClient, err = vpc.NewClientWithAccessKey(regionID, ak, sk)
	if err != nil {
		panic(err)
	}
	eciClient, err = eci.NewClientWithAccessKey(regionID, ak, sk)
	if err != nil {
		panic(err)
	}
}

func main() {
	http.HandleFunc("/", handler)
	port := os.Getenv("FC_SERVER_PORT")
	if port == "" {
		port = "9000"
	}
	http.ListenAndServe(":"+port, nil)
}

func handler(w http.ResponseWriter, req *http.Request) {
	defer func() {
		if r := recover(); r != nil {
			w.Header().Set("x-fc-status", "404")
			w.Write([]byte(fmt.Sprintf("Error: %+v;\nStack: %s", r, string(debug.Stack()))))
		}
	}()
	controlPath := req.Header.Get("x-fc-control-path")
	if controlPath == "/initialize" {
		w.Write([]byte(""))
		return
	}
	invokeHandler(w, req)
}

func invokeHandler(w http.ResponseWriter, req *http.Request) {
	var response respStruct
	response.Header.Action = "Response"
	defer func() {
		respData, _ := json.Marshal(&response)
		w.Write(respData)
	}()
	reqBody, err := ioutil.ReadAll(req.Body)
	if err != nil {
		response.Header.Error = fmt.Sprintf("read request body error, %v", err)
		return
	}
	var request reqStruct
	err = json.Unmarshal(reqBody, &request)
	if err != nil {
		response.Header.Error = fmt.Sprintf("unmarshal request body error, %v", err)
		return
	}
	pass := auth(request.Header.Timestamp, request.Header.Token)
	if !pass {
		response.Header.Error = fmt.Sprintf("auth failture")
		return
	}
	switch request.Header.Action {
	case "RunStart":
		eipInstanceID, eipAddress, err := allocateEipAddress()
		if err != nil {
			response.Header.Error = fmt.Sprintf("allocate eip address error, %v", err)
			return
		}
		err = createContainerGroup(eipInstanceID, request.Payload.Pwd, request.Payload.Port)
		if err != nil {
			response.Header.Error = fmt.Sprintf("create container group error, %v", err)
			return
		}
		response.Payload.IP = eipAddress
	case "RunStop":
		containerGroupIDs, err := describeContainerGroups()
		if err != nil {
			response.Header.Error = fmt.Sprintf("describe container groups error, %v", err)
			return
		}
		for _, containerGroupID := range containerGroupIDs {
			err := deleteContainerGroup(containerGroupID)
			if err != nil {
				response.Header.Error = fmt.Sprintf("delete container group error, %v", err)
				return
			}
		}
		eipInstanceIDs, err := describeEipAddresses()
		if err != nil {
			response.Header.Error = fmt.Sprintf("describe eip addresses error, %v", err)
			return
		}
		for _, eipInstanceID := range eipInstanceIDs {
			err := releaseEipAddress(eipInstanceID)
			if err != nil {
				response.Header.Error = fmt.Sprintf("release eip address error, %v", err)
				return
			}
		}
	default:
		response.Header.Error = fmt.Sprintf("bad action")
	}
}

func auth(timestamp int64, token string) bool {
	now := time.Now().Unix()
	if now-timestamp > 120 || timestamp-now > 120 {
		return false
	}
	tok := sha256.Sum256([]byte(fmt.Sprintf("%v-%v", secret, timestamp)))
	if base64.StdEncoding.EncodeToString(tok[:]) != token {
		return false
	}
	return true
}

func allocateEipAddress() (string, string, error) {
	allocateEipAddressRequest := vpc.CreateAllocateEipAddressRequest()
	allocateEipAddressRequest.Bandwidth = "200"
	allocateEipAddressRequest.AutoPay = requests.NewBoolean(true)
	allocateEipAddressRequest.InstanceChargeType = "PostPaid"
	allocateEipAddressRequest.InternetChargeType = "PayByTraffic"
	allocateEipAddressResponse, err := vpcClient.AllocateEipAddress(allocateEipAddressRequest)
	if err != nil {
		return "", "", err
	}
	return allocateEipAddressResponse.AllocationId, allocateEipAddressResponse.EipAddress, nil
}

func createContainerGroup(eipInstanceID string, pwd string, port int64) error {
	const commandArg = "curl -L -O https://github.com/shadowsocks/go-shadowsocks2/releases/download/v0.1.0/shadowsocks2-linux.gz; gunzip shadowsocks2-linux.gz; chmod 755 shadowsocks2-linux; ./shadowsocks2-linux -s 'ss://AEAD_CHACHA20_POLY1305:%v@:%v' -verbose"
	createContainerRequest := eci.CreateCreateContainerGroupRequest()
	createContainerRequest.RegionId = regionID
	createContainerRequest.SecurityGroupId = securityGroupID
	createContainerRequest.VSwitchId = vSwitchID
	createContainerRequest.ContainerGroupName = "test-group"
	createContainerRequest.RestartPolicy = "Always"
	createContainerRequest.EipInstanceId = eipInstanceID
	createContainerRequestContainer := make([]eci.CreateContainerGroupContainer, 1)
	createContainerRequestContainer[0].Image = "registry-vpc.ap-southeast-1.aliyuncs.com/eci_open/centos:7"
	createContainerRequestContainer[0].Name = "test"
	createContainerRequestContainer[0].Cpu = requests.NewFloat(0.25)
	createContainerRequestContainer[0].Memory = requests.NewFloat(0.5)
	createContainerRequestContainer[0].ImagePullPolicy = "IfNotPresent"
	createContainerRequestContainer[0].WorkingDir = "/home"
	createContainerRequestContainer[0].Command = []string{"/bin/sh"}
	createContainerRequestContainer[0].Arg = []string{"-c", fmt.Sprintf(commandArg, pwd, port)}
	createContainerGroupEnvironmentVar := make([]eci.CreateContainerGroupEnvironmentVar, 1)
	createContainerGroupEnvironmentVar[0].Key = "PATH"
	createContainerGroupEnvironmentVar[0].Value = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	createContainerRequestContainer[0].EnvironmentVar = &createContainerGroupEnvironmentVar
	createContainerRequest.Container = &createContainerRequestContainer
	_, err := eciClient.CreateContainerGroup(createContainerRequest)
	if err != nil {
		return err
	}
	return nil
}

func describeContainerGroups() ([]string, error) {
	describeContainerGroupsRequest := eci.CreateDescribeContainerGroupsRequest()
	describeContainerGroupsRequest.RegionId = regionID
	describeContainerGroupsResponse, err := eciClient.DescribeContainerGroups(describeContainerGroupsRequest)
	if err != nil {
		return nil, err
	}
	var containerGroupIDs []string
	for i := range describeContainerGroupsResponse.ContainerGroups {
		containerGroupIDs = append(containerGroupIDs, describeContainerGroupsResponse.ContainerGroups[i].ContainerGroupId)
	}
	return containerGroupIDs, nil
}

func deleteContainerGroup(containerGroupID string) error {
	deleteContainerGroupRequest := eci.CreateDeleteContainerGroupRequest()
	deleteContainerGroupRequest.ContainerGroupId = containerGroupID
	_, err := eciClient.DeleteContainerGroup(deleteContainerGroupRequest)
	if err != nil {
		return err
	}
	return nil
}

func describeEipAddresses() ([]string, error) {
	describeEipAddressesRequest := vpc.CreateDescribeEipAddressesRequest()
	describeEipAddressesResponse, err := vpcClient.DescribeEipAddresses(describeEipAddressesRequest)
	if err != nil {
		return nil, err
	}
	var eipInstanceIDs []string
	for i := range describeEipAddressesResponse.EipAddresses.EipAddress {
		eipInstanceIDs = append(eipInstanceIDs, describeEipAddressesResponse.EipAddresses.EipAddress[i].AllocationId)
	}
	return eipInstanceIDs, nil
}

func releaseEipAddress(eipInstanceID string) error {
	releaseEipAddressRequest := vpc.CreateReleaseEipAddressRequest()
	releaseEipAddressRequest.AllocationId = eipInstanceID
	_, err := vpcClient.ReleaseEipAddress(releaseEipAddressRequest)
	if err != nil {
		return err
	}
	return nil
}
