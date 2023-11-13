package roles

import (
	"fmt"
	"github.com/edmondop/rbac/internal/rbac"
	"sort"
)

type Role string

type InMemoryUserRoleManager struct {
	keyValueStore map[rbac.User]map[Role]bool
}

func NewInMemoryUserRoleManager() InMemoryUserRoleManager {
	keyValueStore := make(map[rbac.User]map[Role]bool)
	return InMemoryUserRoleManager{keyValueStore: keyValueStore}
}

// Returns true if the user is added to the role, false if she was already assigned
func (usr *InMemoryUserRoleManager) AddUserToRole(user rbac.User, role Role) bool {
	roles, ok := usr.keyValueStore[user]
	if !ok {
		usr.keyValueStore[user] = make(map[Role]bool)
		// Simulating an hashmap
		usr.keyValueStore[user][role] = true
		return true
	} else {
		assigned := roles[role]
		roles[role] = true
		return !assigned
	}

}

func (usr *InMemoryUserRoleManager) RemoveUserFromRole(user rbac.User, role Role) error {
	roles, ok := usr.keyValueStore[user]
	if !ok {
		return fmt.Errorf("no roles assigned to user %s", user)
	}
	assigned := roles[role]
	if assigned {
		roles[role] = false
		return nil
	}
	return fmt.Errorf("user %s does not have role %s, cannot remove it", user, role)
}

func (usr *InMemoryUserRoleManager) GetRolesForUser(user rbac.User) []Role {
	results := make([]Role, 0)
	roles, ok := usr.keyValueStore[user]
	if !ok {
		return results
	}
	for role, assigned := range roles {
		if assigned {
			results = append(results, role)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i] < results[j]
	})
	return results
}
