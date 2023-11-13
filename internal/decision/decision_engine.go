package decision

import (
	"github.com/edmondop/rbac/internal/policy"
	"github.com/edmondop/rbac/internal/rbac"
	"github.com/edmondop/rbac/internal/roles"
)

type RoleManager interface {
	GetRolesForUser(user rbac.User) []roles.Role
}

type PolicyRepository interface {
	GetAssignedPolicies(role roles.Role) []policy.Policy
}

type DecisionEngine struct {
	roleManager      RoleManager
	policyRepository PolicyRepository
}

func NewDecisionEngine(roleManager RoleManager, repository PolicyRepository) DecisionEngine {
	return DecisionEngine{
		roleManager:      roleManager,
		policyRepository: repository,
	}
}

func isAuthorized(resource string, action string, policies []policy.Policy) bool {
	authorized := false
	for _, pol := range policies {
		for _, policyStatement := range pol.PolicyStatements {
			effect := policyStatement.Apply(resource, action)
			if effect != nil {
				if *effect == policy.Deny {
					return false
				} else {
					authorized = true
				}
			}
		}
	}
	return authorized
}

func (d *DecisionEngine) IsAuthorized(request rbac.Request) bool {
	roles := d.roleManager.GetRolesForUser(request.User)
	policies := make([]policy.Policy, 1)
	for _, role := range roles {
		rolePolicies := d.policyRepository.GetAssignedPolicies(role)
		policies = append(policies, rolePolicies...)
	}
	return isAuthorized(request.Resource, request.Action, policies)
}
