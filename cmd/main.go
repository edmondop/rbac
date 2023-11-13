package main

import (
	"context"
	"errors"
	rbacservice "github.com/edmondop/rbac/api/proto"
	"github.com/edmondop/rbac/internal/policy"
	"github.com/edmondop/rbac/internal/rbac"
	"github.com/edmondop/rbac/internal/roles"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"log"
	"net"
)

type UserRoleManager interface {
	AddUserToRole(user rbac.User, role roles.Role) bool
	RemoveUserFromRole(user rbac.User, role roles.Role) error
	GetRolesForUser(user rbac.User) []roles.Role
}

type DecisionEngine interface {
	IsAuthorized(request rbac.Request) bool
}

type PolicyManager interface {
	AddPolicy(policy policy.Policy, roles []roles.Role) policy.PolicyId
	UnassignPolicy(policyId policy.PolicyId, roles []roles.Role) error
	AssignPolicy(policyId policy.PolicyId, roles []roles.Role) error
	UpdatePolicy(policy policy.Policy) error
}

type server struct {
	rbacservice.UnsafeRbacServiceServer
	userRoleManager *UserRoleManager
	decisionEngine  *DecisionEngine
	policyManager   *PolicyManager
}

func convertEffect(effect rbacservice.Effect) policy.Effect {
	if effect == rbacservice.Effect_ALLOW {
		return policy.Allow
	}
	return policy.Deny
}

func convertRoles(strings []string) []roles.Role {
	internalRoles := make([]roles.Role, len(strings))
	for i, s := range strings {
		internalRoles[i] = roles.Role(s)
	}
	return internalRoles
}

func (s *server) AddPolicy(ctx context.Context, request *rbacservice.AddPolicyRequest) (*rbacservice.PolicyIdResponse, error) {
	// Example implementation
	if request == nil {
		return nil, errors.New("empty request")
	}
	policyStatements := make([]policy.PolicyStatement, 0)
	for _, requestPolicyStatement := range request.Statements {
		policyStatement := policy.PolicyStatement{
			StatementId: requestPolicyStatement.StatementId,
			Resources:   requestPolicyStatement.Resources,
			Actions:     requestPolicyStatement.Actions,
			Effect:      convertEffect(requestPolicyStatement.Effect),
		}
		policyStatements = append(policyStatements, policyStatement)
	}
	policy := policy.Policy{
		PolicyStatements: policyStatements,
	}
	policyId := (*s.policyManager).AddPolicy(policy, convertRoles(request.Roles))
	responsePolicyId := rbacservice.PolicyId{
		Value: policyId.String(),
	}
	response := rbacservice.PolicyIdResponse{
		PolicyId: &responsePolicyId,
	}
	return &response, nil
}
func (s *server) AssignPolicy(context.Context, *rbacservice.AssignPolicyRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AssignPolicy not implemented")
}
func (s *server) UnassignPolicy(context.Context, *rbacservice.UnassignPolicyRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UnassignPolicy not implemented")
}
func (s *server) UpdatePolicy(context.Context, *rbacservice.UpdatePolicyRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdatePolicy not implemented")
}
func (s *server) AuthorizeAction(context.Context, *rbacservice.AuthorizeActionRequest) (*rbacservice.AuthorizeActionResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AuthorizeAction not implemented")
}

func (s *server) AddUserToRole(context.Context, *rbacservice.AddUserToRoleRequest) (*rbacservice.AddUserToRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method AddUserToRole not implemented")
}
func (s *server) RemoveUserFromRole(context.Context, *rbacservice.RemoveUserFromRoleRequest) (*emptypb.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RemoveUserFromRole not implemented")
}
func (s *server) GetRolesForUser(context.Context, *rbacservice.GetRolesForUserRequest) (*rbacservice.GetRolesForUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetRolesForUser not implemented")
}

func main() {
	lis, err := net.Listen("tcp", ":50051") // Specify the port
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	s := grpc.NewServer()
	rbacservice.RegisterRbacServiceServer(s, &server{}) // Use your service name

	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
