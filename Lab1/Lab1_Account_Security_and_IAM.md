# Lab 1: Cloud Account Security, Identity and Access Management

**Course:** IKB42603 Cloud Computing Security Essentials  
**Topic:** Identity governance, least privilege, LocalStack IAM and Kubernetes RBAC  
**Environment:** Kali Linux, Docker, LocalStack, AWS CLI, Kubernetes (kind) and kubectl  
**Name:** SITI NUR SALIHAH BINTI AHMAD BALKIS

## Lab Summary and Objectives

This lab explored identity and access management across two local cloud-computing environments. LocalStack was used to practise AWS IAM operations involving users, groups, policies and access keys without connecting to a live AWS account. Kubernetes RBAC was then used to apply and test namespace-based authorization rules. The main objective was to understand how least privilege, credential hygiene and separation of duties reduce security risk.

## Evidence Folder

All screenshots referred to in this report are stored in the `Evidence` folder.

| Evidence File | Purpose |
|---|---|
| `2-Least-privilege.png` | Creation of the administrator group, policy attachment and related commands |
| `2.1-Group-Policy.png` | Creation of the `Admins` group |
| `2.2-Personal-Admin.png` | Creation of the personal administrator account |
| `2.4-Verify-Membership.png` | Verification of membership in the `Admins` group |
| `3.1-create-user.png` | Creation of the analyst account |
| `3.3-ListPermission-User.png` | Verification of the analyst's read-only policy |
| `4.1-access-key.png` | Creation of an analyst access key |
| `4.2-List-access-Keys.png` | Listing of the analyst's access keys |
| `4-Credential&AccessKeys.png` | Deactivation of an old access key |
| `SessionB-Setup.png` | Setup of the kind Kubernetes cluster |
| `5-Env-Namespace.png` | Creation of the `dev` and `prod` namespaces |
| `6-role-bind.png` | Creation of the service account, Role and RoleBinding |
| `7-test.png` | Kubernetes RBAC authorization tests |
| `Verification-RBAC.png` | YAML verification of the RoleBinding |

## Task 1: Map the Cloud Identity Landscape

Before configuring access, it is important to distinguish the main identity concepts used by AWS. Each concept has a different purpose in controlling who can access resources and what actions they may perform.

| Concept | AWS Term | Purpose |
|---|---|---|
| Account owner with unrestricted power | Root user | The initial identity that owns the account and has complete access to resources and billing. It must be strongly protected and reserved for exceptional account-level activities. |
| Identity for a person or application | IAM User | A named identity that may receive credentials and permissions for long-term access to cloud services. |
| Set of permission rules | IAM Policy | A JSON document that specifies allowed or denied actions and the resources to which those rules apply. |
| Managed collection of identities | IAM Group | A collection of IAM users that can receive common policies, making access administration more consistent. |
| Assumable temporary identity | IAM Role | An identity that provides temporary permissions when assumed, reducing dependence on permanent credentials. |

## Session A: LocalStack IAM

### Environment Setup Verification

Before performing any IAM configuration, the AWS CLI was configured to communicate with the LocalStack endpoint. The `sts get-caller-identity` command was executed to verify that the AWS CLI was successfully connected to the local cloud environment. The output displays the default LocalStack account ID (`000000000000`), confirming that all subsequent IAM operations will be performed locally rather than on the real AWS cloud.

![LocalStack IAM Verification](Evidence/1._LocalStack_Identity_Verification.png)

**Figure 1.:** Verification of the AWS CLI connection to the LocalStack IAM environment using the `sts get-caller-identity` command.
## Task 2: Create a Least-Privilege Admin

Rather than using the root identity for routine administration, a named administrator was created. Administrative access was assigned through a group so that permissions could be centrally managed.

### Step 2.1: Create the Admins Group

To implement centralized permission management, an IAM group named `Admins` was created in the LocalStack environment. After the group was successfully created, the managed `AdministratorAccess` policy was attached to it. Assigning permissions through a group allows administrator privileges to be inherited by group members instead of attaching policies directly to individual users. This approach simplifies permission management and follows AWS IAM best practices.

**Create the Admins group**

```bash
aws $EP iam create-group --group-name Admins
```

![Create Admins Group](Evidence/2.1_create_admins_group.png)

**Attach the AdministratorAccess policy**

```bash
aws $EP iam attach-group-policy --group-name Admins \
    --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

![Attach AdministratorAccess Policy](Evidence/2.1_attach_admin_policy.png)

**Figure 2.1:** Creation of the `Admins` IAM group and attachment of the `AdministratorAccess` managed policy in the LocalStack environment.

### Step 2.2: Create a Personal Administrator Account

A dedicated IAM user named `CloudAdmin_Salihah` was created to perform administrative tasks instead of using the root account. Creating a separate administrator account improves accountability and follows the security best practice of avoiding the use of the root identity for routine administration. The command output confirms that the user was created successfully.

```bash
aws $EP iam create-user --user-name CloudAdmin_Salihah
```

![Create Personal Administrator Account](Evidence/2.2_create_cloudadmin_user.png)

**Figure 2.2:** Successful creation of the `CloudAdmin_Salihah` IAM user in the LocalStack environment.

### Step 2.3: Add the Administrator User to the Admins Group

After creating the personal administrator account, the user `CloudAdmin_Salihah` was added to the `Admins` group. This allows the user to inherit the permissions assigned to the group instead of attaching administrator policies directly to the user account. Managing permissions through groups improves consistency and simplifies future access management.

```bash
aws $EP iam add-user-to-group --group-name Admins \
    --user-name CloudAdmin_Salihah
```

![Add user to Admins group](Evidence/2.3_add_user_to_admins_group.png)

**Figure 2.3:** Command used to add the `CloudAdmin_Salihah` user to the `Admins` IAM group.

### Step 2.4: Verify Administrator Group Membership

The `get-group` command was executed to verify that the `CloudAdmin_Salihah` user had been successfully added to the `Admins` group. The output displays both the group information and the user details, confirming that the administrator account is now a member of the group and will inherit the permissions assigned to it.

```bash
aws $EP iam get-group --group-name Admins
```

![Verify Admins Group Membership](Evidence/2.4_verify_admin_group_membership.png)

**Figure 2.4:** Verification that the `CloudAdmin_Salihah` user is a member of the `Admins` IAM group.

## Task 3: Enforce Least Privilege with a Scoped Policy

A separate analyst identity was created for work that does not require administrative control. Giving this user only read access illustrates how permissions can be matched to a job function.

### Step 3.1: Create the Analyst User

A dedicated IAM user named `Analyst_Suraya` was created to represent an analyst account with limited access. This user is intended to perform tasks that do not require administrative privileges, supporting the principle of least privilege by separating administrative and non-administrative responsibilities.

```bash
aws $EP iam create-user --user-name Analyst_Suraya
```

The command returned the user details, including the user name, ARN and creation timestamp, confirming that the `Analyst_Suraya` account was successfully created.

![Create Analyst User](Evidence/3.1_create_analyst_user.png)

**Figure 3.1:** Successful creation of the `Analyst_Suraya` IAM user in the LocalStack environment.

### Step 3.2: Attach the AmazonS3ReadOnlyAccess Policy

To enforce the principle of least privilege, the `AmazonS3ReadOnlyAccess` managed policy was attached to the `Analyst_Suraya` user. This policy grants read-only access to Amazon S3 resources, allowing the user to view information without creating, modifying or deleting any objects. Assigning only the required permissions helps reduce potential security risks.

```bash
aws $EP iam attach-user-policy --user-name Analyst_Suraya \
    --policy-arn arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess
```

![Attach AmazonS3ReadOnlyAccess Policy](Evidence/3.2_attach_s3_readonly_policy.png)

**Figure 3.2:** Command used to attach the `AmazonS3ReadOnlyAccess` managed policy to the `Analyst_Suraya` IAM user.

### Step 3.3: Verify the Attached Policy

The attached policies for the `Analyst_Suraya` user were verified using the AWS CLI. The output shows that only the `AmazonS3ReadOnlyAccess` managed policy is assigned to the user. This confirms that the analyst account has read-only permissions and does not possess unnecessary administrative privileges, demonstrating the implementation of the principle of least privilege.

```bash
aws $EP iam list-attached-user-policies --user-name Analyst_Suraya
```

![Verify Attached User Policy](Evidence/3.3-verify-attached-user-policy.png)

**Figure 3.3:** Verification that the `AmazonS3ReadOnlyAccess` managed policy is attached to the `Analyst_Suraya` IAM user.

### Least-Privilege Explanation

The `Analyst_Suraya` identity is limited to viewing S3 information and objects permitted by the managed policy. If its credentials were compromised, an attacker would not gain administrator privileges through this account. The identity could not use IAM administration capabilities to create privileged users or change policies, and its read-only scope would prevent write or delete operations in S3. Restricting the account in this way reduces the possible impact, or blast radius, of a credential compromise.

## Task 4: Credential Hygiene and Access Keys

Access keys are long-term credentials and therefore require careful handling. This task demonstrated their creation, inspection and deactivation as part of a basic credential-rotation process.

### Step 4.1: Create an Access Key

An access key was generated for the `Analyst_Suraya` IAM user to enable programmatic access to cloud services. The generated credentials consist of an Access Key ID and a Secret Access Key, which are used to authenticate API requests. In practice, these credentials should be protected and never exposed in public repositories or shared with unauthorized individuals.

```bash
aws $EP iam create-access-key --user-name Analyst_Suraya
```

The command successfully generated a new access key for the analyst account, confirming that the user is able to authenticate programmatically when the assigned permissions are required.

![Create Access Key](Evidence/4.1-create-access-key.png)

**Figure 4.1:** Successful creation of an access key for the `Analyst_Suraya` IAM user.

### Step 4.2: List Access Keys

The access keys associated with the `Analyst_Suraya` account were listed to verify that the newly created credentials were successfully registered. The output displays the Access Key ID, user name, creation date and current status. The status `Active` confirms that the access key is valid and can be used for programmatic authentication.

```bash
aws $EP iam list-access-keys --user-name Analyst_Suraya
```

![List Access Keys](Evidence/4.2_list_access_keys.png)

**Figure 4.2:** Verification of the active access key assigned to the `Analyst_Suraya` IAM user.

### Step 4.3: Deactivate the Access Key

To demonstrate credential hygiene, the access key associated with the `Analyst_Suraya` account was deactivated using the AWS CLI. After updating the key status, the access keys were listed again to verify the change. The output shows that the access key status is now `Inactive`, confirming that the credentials can no longer be used for authentication while still remaining in the account for management purposes.

```bash
aws $EP iam update-access-key --user-name Analyst_Suraya \
    --access-key-id LKIAQAAAAAAACJZHI7QN --status Inactive

aws $EP iam list-access-keys --user-name Analyst_Suraya
```

![Deactivate Access Key](Evidence/4.3_deactivate_access_key.png)

**Figure 4.3:** Verification that the access key for the `Analyst_Suraya` IAM user has been successfully changed to the `Inactive` state.

## Session B: Kubernetes RBAC

The second part of the lab applied access control to Kubernetes. Unlike IAM policy assignment in LocalStack, these tests produced authorization decisions for a service account within separated namespaces.

### Setup: Create Local Kubernetes Cluster

Commands:

```bash
kind create cluster --name ccse-lab1
kubectl cluster-info --context kind-ccse-lab1
kubectl get nodes
```

The kind cluster named `ccse-lab1` was created, and kubectl was configured to communicate with the `kind-ccse-lab1` context.

![Kubernetes cluster setup](Evidence/SessionB-Setup.png)

## Task 5: Separate Environments with Namespaces

Namespaces provide logical separation for resources within one Kubernetes cluster. Separate `dev` and `prod` namespaces were created to represent development and production environments.

Commands:

```bash
kubectl create namespace dev
kubectl create namespace prod
kubectl get namespaces
```

Both namespaces were created and appeared with an `Active` status.

![Development and production namespaces](Evidence/5-Env-Namespace.png)

## Task 6: Define a Role and Bind It

Kubernetes RBAC separates the description of permissions from the assignment of those permissions. A service account was created first, followed by a namespaced Role and a RoleBinding.

### Step 6.1: Create Service Account

Command:

```bash
kubectl create serviceaccount dev-user -n dev
```

This created the `dev-user` service account inside the `dev` namespace.

### Step 6.2: Create Pod Reader Role

Command:

```bash
kubectl create role pod-reader -n dev \
    --verb=get,list,watch --resource=pods
```

The namespaced `pod-reader` Role permits only the `get`, `list` and `watch` verbs for pod resources in `dev`.

### Step 6.3: Create RoleBinding

Command:

```bash
kubectl create rolebinding dev-user-binding -n dev \
    --role=pod-reader --serviceaccount=dev:dev-user
```

The `dev-user-binding` RoleBinding assigned the permissions in `pod-reader` to the `dev-user` service account.

![Service account, Role and RoleBinding creation](Evidence/6-role-bind.png)

## Task 7: Test Access Control

The fully qualified service-account identity was saved in a shell variable for the authorization tests:

```bash
SA=system:serviceaccount:dev:dev-user
```

This value represents the `dev-user` service account located in the `dev` namespace.

### Test 1: List Pods in Dev

Command:

```bash
kubectl auth can-i list pods -n dev --as=$SA
```

Result:

```text
yes
```

The request was allowed because the `pod-reader` Role explicitly includes the `list` verb for pods in `dev`.

### Test 2: Delete Pods in Dev

Command:

```bash
kubectl auth can-i delete pods -n dev --as=$SA
```

Result:

```text
no
```

The request was denied because `delete` was not included among the verbs granted by the Role.

### Test 3: List Pods in Prod

Command:

```bash
kubectl auth can-i list pods -n prod --as=$SA
```

Result:

```text
no
```

Although the service account could list pods in `dev`, the same action was rejected in `prod`. The Role and RoleBinding are limited to the namespace in which they were created and therefore provide no authorization in `prod`.

![RBAC authorization test results](Evidence/7-test.png)

### Authentication and Authorization

Authentication establishes the identity making a request, while authorization decides whether that authenticated identity may perform the requested action. Kubernetes recognized `system:serviceaccount:dev:dev-user` as a valid service-account identity. RBAC then allowed pod listing in `dev`, but rejected pod deletion in `dev` and pod listing in `prod` because those capabilities were outside the assigned permissions.

## RBAC Verification Command

The RoleBinding configuration was inspected directly with the required verification command:

```bash
kubectl get rolebinding dev-user-binding -n dev -o yaml
```

Output:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  creationTimestamp: "2026-07-29T05:48:38Z"
  name: dev-user-binding
  namespace: dev
  resourceVersion: "701"
  uid: 91124053-fdc5-418a-a916-ec078374971c
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: dev-user
  namespace: dev
```

![RoleBinding YAML verification](Evidence/Verification-RBAC.png)

The YAML shows that `dev-user-binding` refers to the `pod-reader` Role and names `dev-user` in the `dev` namespace as its subject. This confirms the intended RBAC relationship.

## Short-Answer Questions

### Q1. Why is attaching policies to groups better than attaching them directly to users?

Group-based policy assignment makes permissions easier to maintain, review and audit. When several people need the same level of access, an administrator can manage one group policy instead of repeating the configuration for every user. Adding or removing a person from the group then changes access consistently and lowers the chance of configuration errors.

### Q2. What is the difference between an IAM User and an IAM Role?

An IAM User is a persistent identity generally associated with a person or application and may use long-term credentials such as an access key. An IAM Role is assumed when required and normally issues temporary credentials. Roles are especially suitable for services and short-lived access because permanent credentials do not need to be embedded or continuously stored.

### Q3. Explain least privilege using the Analyst account, and how it reduces blast radius if compromised.

`Analyst_Suraya` received only `AmazonS3ReadOnlyAccess`, which was appropriate for an analyst who needs to inspect rather than change information. If the credentials were stolen, the attacker would be constrained by the same read-only policy and would not obtain IAM administration or S3 modification privileges. The limited permission set therefore reduces the number and severity of actions possible through the compromised account.

### Q4. In Kubernetes, what is the difference between a Role and a RoleBinding?

A Role contains permission rules, including the resources and verbs allowed within a namespace. A RoleBinding assigns those rules to a user, group or service account. In this exercise, `pod-reader` described the permitted pod-reading actions, while `dev-user-binding` granted them to `dev-user`.

### Q5. Why did the developer service account fail to access prod, and which security principle does that demonstrate?

The service account failed because its Role and RoleBinding existed only in `dev`; no binding granted it permission in `prod`. This result demonstrates least privilege as well as environment separation, since the identity can operate only within its approved scope.

## Security Best-Practices Checklist

- [x] A dedicated administrator, `CloudAdmin_Salihah`, was used instead of relying on the root identity for routine work.
- [x] Administrator permissions were managed through the `Admins` group rather than attached directly to the personal administrator.
- [x] The analyst identity, `Analyst_Suraya`, was restricted with `AmazonS3ReadOnlyAccess`.
- [x] Access-key creation, review and deactivation were performed to demonstrate credential rotation.
- [x] Kubernetes RBAC denied pod deletion in `dev` and pod listing in `prod` because neither action was authorized.

## Conclusion

This lab showed that secure access depends on granting identities only the permissions required for their responsibilities. In LocalStack IAM, a named administrator inherited centrally managed access from the `Admins` group, while `Analyst_Suraya` was restricted to read-only S3 operations. Creating and deactivating an access key also highlighted the importance of protecting and rotating long-term credentials.

Kubernetes RBAC reinforced the same principle through a different authorization model. The `dev-user` service account could read pods in its assigned namespace but could neither delete them nor use the same permission in `prod`. Together, the two exercises demonstrated how group-based IAM policies, scoped identities, namespace boundaries and explicit role bindings help limit unauthorized activity and reduce the impact of compromised credentials.
