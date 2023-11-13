package policy

import (
	"errors"
	"github.com/edmondop/rbac/internal/rbac"
	"github.com/edmondop/rbac/internal/roles"
	"github.com/google/uuid"
	"log"
)

type Effect int

const (
	Allow Effect = iota
	Deny
)

type PolicyId uuid.UUID

func (p *PolicyId) String() string {
	return uuid.UUID(*p).String()
}

type PolicyStatement struct {
	StatementId string
	Resources   []string
	Actions     []string
	Effect      Effect
}

func (p *PolicyStatement) Apply(resource string, action string) *Effect {
	for _, policyResource := range p.Resources {
		for _, policyAction := range p.Actions {
			if policyAction == action && resource == policyResource {
				return &p.Effect
			}
		}
	}
	return nil
}

type Policy struct {
	policyId         *PolicyId
	PolicyStatements []PolicyStatement
}

type RoleManager interface {
	AssignUserToGroup(user rbac.User, role roles.Role)
}

type InMemoryPolicyRepository struct {
	policiesKeyValueStore map[PolicyId]Policy
	policiesByRoleIndex   map[roles.Role]map[PolicyId]bool
}

func New() InMemoryPolicyRepository {
	return InMemoryPolicyRepository{
		policiesKeyValueStore: make(map[PolicyId]Policy),
		policiesByRoleIndex:   make(map[roles.Role]map[PolicyId]bool),
	}
}

func (pe *InMemoryPolicyRepository) AddPolicy(policy Policy, roles []roles.Role) PolicyId {
	policyId := PolicyId(uuid.New())
	pe.policiesKeyValueStore[policyId] = policy
	policy.policyId = &policyId
	for _, role := range roles {
		pe.policiesByRoleIndex[role][policyId] = true
	}
	return policyId
}

func (pe *InMemoryPolicyRepository) UnassignPolicy(policyId PolicyId, roles []roles.Role) error {
	_, ok := pe.policiesKeyValueStore[policyId]
	if !ok {
		return errors.New("policy not present in this policy engine, cannot unassign it to roles")
	}
	for _, role := range roles {
		pe.policiesByRoleIndex[role][policyId] = false
	}
	return nil
}

func (pe *InMemoryPolicyRepository) AssignPolicy(policyId PolicyId, roles []roles.Role) error {
	_, ok := pe.policiesKeyValueStore[policyId]
	if !ok {
		return errors.New("policy not present in this policy engine, cannot assign it to roles")
	}
	for _, role := range roles {
		pe.policiesByRoleIndex[role][policyId] = true
	}
	return nil
}

func (pe *InMemoryPolicyRepository) UpdatePolicy(policy Policy) error {
	if policy.policyId == nil {
		return errors.New("policy never added to policy engine before, cannot updated it")
	}
	policy, ok := pe.policiesKeyValueStore[*policy.policyId]
	if !ok {
		return errors.New("policy not present in this policy engine, cannot update")
	}
	pe.policiesKeyValueStore[*policy.policyId] = policy
	return nil
}

func (pe *InMemoryPolicyRepository) GetAssignedPolicies(role roles.Role) []Policy {
	policies, ok := pe.policiesByRoleIndex[role]
	result := make([]Policy, 0)
	for !ok {
		return result
	}
	for policyId, assignment := range policies {
		if assignment {
			policy, ok := pe.policiesKeyValueStore[policyId]
			if !ok {
				log.Fatalf("policy with id %s present in index but absent in policy store", policyId)
			}
			result = append(result, policy)
		}
	}
	return result
}
