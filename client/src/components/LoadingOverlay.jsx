import "./LoadingOverlay.css";

export default function LoadingOverlay({
  text = "Loading CyberShield..."
}) {
  return (
    <div className="loading-overlay">
      <div className="loading-card">

        <div className="loading-ring" />

        <h2>{text}</h2>

        <p>
          Collecting threat intelligence...
        </p>

      </div>
    </div>
  );
}