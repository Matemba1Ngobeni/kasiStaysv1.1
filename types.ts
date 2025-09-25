export enum UserRole {
  Student = 'student',
  Landlord = 'landlord',
  ServiceProvider = 'provider',
  Admin = 'admin',
}

export interface UserProfile {
  uid: string;
  email: string | null;
  role: UserRole;
  isVerified?: boolean;
  profileImageUrl?: string;
  university?: string;
  fieldOfStudy?: string;
  memberSince?: string;
}

export interface Listing {
  id: string;
  landlordId: string;
  title: string;
  price: number;
  imageUrl: string;
  location: string;
  isVerified: boolean;
  gpsCoordinates: {
    lat: number;
    lng: number;
  };
}

export interface ServiceProvider {
  id: string;
  name: string;
  service: string;
  imageUrl: string;
  contact: string;
}

export enum MaintenanceRequestStatus {
  Open = 'Open',
  InProgress = 'In Progress',
  Resolved = 'Resolved',
}

export interface MaintenanceRequest {
  id: string;
  listingId: string;
  studentId: string;
  landlordId: string;
  issue: string;
  status: MaintenanceRequestStatus;
  createdAt: string;
}

export interface Conversation {
  id: string;
  participantIds: string[];
  listingId: string;
  lastMessageTimestamp: number;
  lastMessage: string;
}

export interface Message {
  id: string;
  conversationId: string;
  senderId: string;
  text: string;
  timestamp: number;
}