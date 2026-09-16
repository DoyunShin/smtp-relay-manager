export type Envelope<T> = {
  status: number;
  message: string;
  data: T | null;
};

export type User = {
  id: string;
  username: string;
  active: boolean;
  is_operator: boolean;
  created_at: string;
};

export type SessionData = {
  user: User;
  csrf_token: string;
};

export type Invitation = {
  id: string;
  expires_at: string;
  used_at: string | null;
  invitation_url: string | null;
  token: string | null;
};

export type OperatorUser = User & {
  invitation: Invitation | null;
};

export type PageData<T> = {
  items: T[];
  total: number;
  limit: number;
  offset: number;
};

export type DomainStatus = 'pending' | 'approved' | 'rejected';
export type DomainRole = 'owner' | 'admin' | null;

export type Domain = {
  id: string;
  name: string;
  status: DomainStatus;
  owner_user_id: string;
  owner_username: string;
  created_at: string;
};

export type Address = {
  id: string;
  domain_id: string;
  address: string;
};

export type Admin = {
  id: string;
  username: string;
  active: boolean;
};

export type Grant = {
  id: string;
  domain_id: string;
  user_id: string;
  username: string;
  address: string;
};

export type SmtpSecurity = 'none' | 'starttls' | 'tls';
export type SmtpAuthType = 'none' | 'password';

export type SmtpConfig = {
  domain_id: string;
  host: string;
  port: number;
  security: SmtpSecurity;
  auth_type: SmtpAuthType;
  username: string | null;
  password_set: boolean;
};

export type DomainDetail = {
  domain: Domain;
  role: DomainRole;
  smtp_config: SmtpConfig | null;
  addresses: Address[];
  admins: Admin[];
  grants: Grant[];
};

export type Scope = {
  domain_id: string;
  address: string;
};

export type Credential = {
  id: string;
  user_id: string;
  name: string;
  scopes: Scope[];
  expires_at: string | null;
  revoked_at: string | null;
  created_at: string;
};

export type CreatedCredential = {
  credential: Credential;
  username: string;
  token: string;
};

export type DeliveryStatus = 'pending' | 'accepted' | 'failed' | 'unknown';

export type DeliveryLog = {
  id: string;
  user_id: string | null;
  credential_id: string | null;
  domain_id: string | null;
  sender: string;
  recipients: string[];
  status: DeliveryStatus;
  error_code: string | null;
  error_stage: string | null;
  error_message: string | null;
  created_at: string;
  updated_at: string;
};

export type CreatedUser = {
  user: User;
  invitation: Invitation;
};
