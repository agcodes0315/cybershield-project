import { Shield } from 'lucide-react';

export default function LoadingScreen() {
  return (
    <div className="loading-screen">
      <div className="loading-screen-content">
        <div className="loading-shield">
          <Shield size={36} strokeWidth={2} />
        </div>

        <h1>CyberShield</h1>

        <p>Initializing security operations...</p>

        <div className="loading-progress">
          <span />
        </div>
      </div>
    </div>
  );
}