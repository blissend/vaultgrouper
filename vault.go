package vault

import (
	"encoding/json"
	"fmt"
	"github.com/hashicorp/vault/api"
	"io/ioutil"
	"reflect"
	"strings"
)

// Vault auth data
type Vault struct {
	Token       string                 `json:"token"`
	RoleName    string                 `json:"role_name"`
	RoleID      string                 `json:"role_id"`
	SecretID    string                 `json:"secret_id"`
	Value       map[string]interface{} `json:"value"`
	Username    string                 `json:"username"`
	Password    string                 `json:"password"`
	Address     string                 `json:"address"`
	AppToken    string                 `json:"app_token"`
	AppRoleID   string                 `json:"app_role_id"`
	AppRoleName string                 `json:"app_role_name"`
	AppGroup    string                 `json:"group"`
}

// Client sets up client connection for Vault API
func (v *Vault) Client() (*api.Client, error) {
	// Setup the address/creds
	var err error
	var filename string
	v.Address = ""     // CHANGE ME
	v.AppToken = ""    // CHANGE ME
	v.AppRoleID = ""   // CHANGE ME
	v.AppRoleName = "" // CHANGE ME
	if filename != "" {
		// Find path due shifting nature of where test/exec is run
		relatives := []string{"../", "../../", "./"}
		var file []byte
		var path string
		for _, val := range relatives {
			path = val + filename
			file, err = ioutil.ReadFile(path)
			if err == nil {
				break
			}
		}
		if err != nil {
			log.Debug(err.Error())
			return nil, err
		}
		json.Unmarshal(file, &v)
	}

	// Use default config but with our custom URL address
	config := api.DefaultConfig()
	config.Address = v.Address

	// Setup our client
	c, err := api.NewClient(config)
	if err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	return c, nil
}

// Auth uses Vault.Client to authenticate against Vault API
func (v *Vault) Auth() (map[string]interface{}, error) {
	// Setup client if necessary
	var err error
	client, err := v.Client()
	if err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	// Determine method
	method := ""
	log.Info(v)
	if v.Username == "vault-user" && v.Password == "vault-user" {
		// For testing only
		method = "userpass"
	} else if v.Username != "" {
		method = "ldap"
	} else if v.RoleName != "" {
		method = "approle"
	} else {
		err = fmt.Errorf("unknown auth method")
		log.Debug(err.Error())
		return nil, fmt.Errorf("unknown auth method")
	}

	// Authenticate based on method
	data := make(map[string]interface{})
	switch method {
	case "approle":
		if v.Token == "" || v.RoleID == "" || v.RoleName == "" {
			err = fmt.Errorf("requires token, role_id and role_name for authentication")
			log.Error(err.Error())
			return nil, fmt.Errorf("requires token, role_id and role_name for authentication")
		}

		// Get secret_id
		client.SetToken(v.Token)
		path := fmt.Sprintf("auth/approle/role/%s/secret-id", v.RoleName)
		resp, err := Call(client, "write", path, data)
		if err != nil {
			log.Printf(err.Error())
			return nil, err
		}
		v.SecretID = resp.Data["secret_id"].(string)

		// Get new token with secret_id
		data["role_id"] = v.RoleID
		data["secret_id"] = v.SecretID
		path = "auth/approle/login"
		resp, err = Call(client, "write", path, data)
		client.SetToken(resp.Auth.ClientToken)
		data["client_token"] = resp.Auth.ClientToken
		ttl, _ := resp.TokenTTL()
		data["ttl"] = int(ttl.Seconds())
		return data, err

	case "ldap":
		if v.Username == "" || v.Password == "" {
			err = fmt.Errorf("requires username and password for authentication")
			log.Debug(err.Error())
			return nil, err
		}
		path := fmt.Sprintf("auth/ldap/login/%s", v.Username)

		resp, err := Call(client, "write", path, map[string]interface{}{"password": v.Password})
		if err != nil {
			return nil, err
		}
		data := make(map[string]interface{})
		data["client_token"] = resp.Auth.ClientToken
		ttl, _ := resp.TokenTTL()
		data["ttl"] = int(ttl.Seconds())
		return data, err

	case "userpass":
		// For testing only
		if v.Username == "" || v.Password == "" {
			err = fmt.Errorf("requires username and password for authentication")
			log.Debug(err.Error())
			return nil, fmt.Errorf("requires username and password for authentication")
		}
		data := make(map[string]interface{})
		path := fmt.Sprintf("auth/userpass/login/%s", v.Username)
		data["password"] = v.Password

		resp, err := Call(client, "write", path, data)
		if err != nil {
			log.Debug(err.Error())
			err = fmt.Errorf("Bad Credentials: " + err.Error())
			return data, err
		}
		data["client_token"] = resp.Auth.ClientToken
		ttl, _ := resp.TokenTTL()
		data["ttl"] = int(ttl.Seconds())
		return data, err

	default:
		err = fmt.Errorf("method %s not yet implmented", method)
		log.Debug(err.Error())
		return nil, err
	}
}

// Group creates/deletes app groups if admin
func (v *Vault) Group(method string) (string, error) {
	// Check payload/setup data
	if v.AppGroup == "" {
		err := fmt.Errorf("requires group name")
		log.Debug(err.Error())
		return "failure", err
	}
	if strings.ToLower(v.AppGroup) == "admin" || strings.ToLower(v.AppGroup) == "login" {
		err := fmt.Errorf("group name can't be login or admin")
		log.Debug(err.Error())
		return "failure", err
	}
	if v.Token == "" {
		err := fmt.Errorf("requires token")
		log.Debug(err.Error())
		return "failure", err
	}

	// Setup client
	client, err := v.Client()
	if err != nil {
		log.Debug(err.Error())
		return "failure", err
	}
	client.SetToken(v.Token)

	// Check for admin rights
	resp, err := Call(client, "read", "auth/token/lookup-self", nil)
	if err != nil {
		log.Debug(err.Error())
		return "failure", err
	}
	if SliceExists(resp.Data["policies"], "app-admin") == false && SliceExists(resp.Data["policies"], "app-admin-test") == false {
		err := fmt.Errorf("not an app admin")
		log.Debug(err.Error())
		return "failure", err
	}

	switch method {
	case "create":
		// Create k/v store
		if len(v.Value) == 0 {
			v.Value = make(map[string]interface{})
			v.Value["permissions"] = []string{}
		}
		path := fmt.Sprintf("app/%s", v.AppGroup)
		resp, err = Call(client, "write", path, v.Value)
		if err != nil {
			log.Debug(err.Error())
			return "failure", err
		}

		// Create policy to k/v store
		path = fmt.Sprintf("sys/policy/app-%s", v.AppGroup)
		policy := fmt.Sprintf(
			"path \"app/%s\" {capabilities = [\"read\", \"list\", \"update\", \"create\", \"delete\", \"sudo\"]}",
			v.AppGroup)
		data := make(map[string]interface{})
		data["policy"] = policy
		resp, err = Call(client, "write", path, data)
		if err != nil {
			log.Debug(err.Error())
			return "failure", err
		}
	case "delete":
		// Destroy k/v store
		path := fmt.Sprintf("app/%s", v.AppGroup)
		resp, err = Call(client, "delete", path, nil)
		if err != nil {
			log.Debug(err.Error())
			return "failure", err
		}

		// Destroy policy to k/v store
		path = fmt.Sprintf("sys/policy/app-%s", v.AppGroup)
		resp, err = Call(client, "delete", path, nil)
		if err != nil {
			log.Debug(err.Error())
			return "failure", err
		}
	default:
		err := fmt.Errorf("invalid path")
		log.Debug(err.Error())
		return "failure", err
	}

	return "success", nil
}

// Verify makes sure Vault token exists and is part of group
func (v *Vault) Verify(token string, group string) (*api.Secret, error) {
	var err error
	var resp *api.Secret

	// Setup client
	client, err := v.Client()
	if err != nil {
		log.Debug(err.Error())
		return nil, err
	}

	// Check if token exists
	if token != "" {
		client.SetToken(token)
		resp, err = Call(client, "read", "auth/token/lookup-self", nil)
		if err != nil {
			log.Debug(err.Error())
			return nil, err
		}
	} else {
		return nil, fmt.Errorf("requires token to verify")
	}

	// Check if token has policy associated with group
	if group != "" && token != "" {
		client.SetToken(v.AppToken)
		if group == "app-admin" {
			if SliceExists(resp.Data["policies"], "app-admin") == false &&
				SliceExists(resp.Data["policies"], "app-admin-test") == false {
				return nil, fmt.Errorf("not an app admin")
			}
		} else {
			if SliceExists(resp.Data["policies"], group) == false {
				return nil, fmt.Errorf("not part of %s", group)
			}
		}
	}

	return resp, nil
}

// SliceExists simple checks for existance of item in slice
func SliceExists(slice interface{}, item interface{}) bool {
	s := reflect.ValueOf(slice)

	if s.Kind() != reflect.Slice {
		panic("SliceExists() given a non-slice type")
	}

	for i := 0; i < s.Len(); i++ {
		if s.Index(i).Interface() == item {
			return true
		}
	}

	return false
}

// Call is a simple func wrapper for all Vault API Calls
func Call(client *api.Client, method string, path string, data map[string]interface{}) (*api.Secret, error) {
	switch method {
	case "read":
		return client.Logical().Read(path)
	case "delete":
		return client.Logical().Delete(path)
	case "write":
		return client.Logical().Write(path, data)
	default:
		return nil, fmt.Errorf("unsupported method")
	}
}
