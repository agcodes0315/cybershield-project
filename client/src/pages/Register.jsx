import { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { auth } from '../services/api';

export default function Register() {
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    email: '',
    username: '',
    password: '',
    confirmPassword: '',
  });

  const [acceptedTerms, setAcceptedTerms] = useState(false);
  const [error, setError] = useState('');
  const [success, setSuccess] = useState('');
  const [loading, setLoading] = useState(false);

  const inputStyle = {
    width: '100%',
    padding: '14px 16px 14px 48px',
    background: 'rgba(15, 23, 42, 0.58)',
    border: '1px solid #1e293b',
    borderRadius: '12px',
    color: 'white',
    fontSize: '0.95rem',
    outline: 'none',
    transition: 'all 0.2s ease',
    fontFamily: 'Outfit, sans-serif',
    boxSizing: 'border-box',
  };

  const handleInputChange = (event) => {
    const { name, value } = event.target;

    setFormData((previousData) => ({
      ...previousData,
      [name]: value,
    }));

    setError('');
    setSuccess('');
  };

  const validateForm = () => {
    const email = formData.email.trim();
    const username = formData.username.trim();
    const password = formData.password;
    const confirmPassword = formData.confirmPassword;

    if (!email || !username || !password || !confirmPassword) {
      return 'All fields are required.';
    }

    const validEmail = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!validEmail.test(email)) {
      return 'Please enter a valid email address.';
    }

    if (username.length < 3) {
      return 'Username must contain at least 3 characters.';
    }

    if (!/^[a-zA-Z0-9._-]+$/.test(username)) {
      return 'Username can contain only letters, numbers, dots, underscores, and hyphens.';
    }

    if (password.length < 8) {
      return 'Password must contain at least 8 characters.';
    }

    if (password !== confirmPassword) {
      return 'Passwords do not match.';
    }

    if (!acceptedTerms) {
      return 'Please accept the terms and conditions.';
    }

    return '';
  };

  const getBackendError = (requestError) => {
    const responseData = requestError?.response?.data;

    if (typeof responseData === 'string' && responseData.trim()) {
      return responseData;
    }

    if (responseData?.error) {
      return responseData.error;
    }

    if (responseData?.message) {
      return responseData.message;
    }

    if (requestError?.code === 'ERR_NETWORK') {
      return 'Cannot reach the API gateway. Confirm that it is running on port 5000.';
    }

    return 'Registration failed. Please try again.';
  };

  const handleSubmit = async (event) => {
    event.preventDefault();

    setError('');
    setSuccess('');

    const validationError = validateForm();

    if (validationError) {
      setError(validationError);
      return;
    }

    setLoading(true);

    const registrationData = {
      email: formData.email.trim().toLowerCase(),
      username: formData.username.trim(),
      password: formData.password,
    };

    try {
      console.log('Registration payload:', {
        email: registrationData.email,
        username: registrationData.username,
        password: '[hidden]',
      });

      const response = await auth.register(registrationData);

      console.log('Registration response:', response.data);

      setSuccess('Account created successfully. Redirecting to login...');

      setFormData({
        email: '',
        username: '',
        password: '',
        confirmPassword: '',
      });

      setAcceptedTerms(false);

      window.setTimeout(() => {
        navigate('/login', {
          replace: true,
          state: {
            message: 'Registration successful. Please sign in.',
          },
        });
      }, 1000);
    } catch (requestError) {
      console.error('Registration request failed:', requestError);
      console.error('Backend response:', requestError?.response?.data);

      setError(getBackendError(requestError));
    } finally {
      setLoading(false);
    }
  };

  const focusInput = (event) => {
    event.target.style.borderColor = '#06b6d4';
    event.target.style.boxShadow = '0 0 0 3px rgba(6,182,212,0.1)';
  };

  const blurInput = (event) => {
    event.target.style.borderColor = '#1e293b';
    event.target.style.boxShadow = 'none';
  };

  return (
    <div
      style={{
        display: 'flex',
        minHeight: '100vh',
        background: '#050a14',
        overflow: 'hidden',
        fontFamily: 'Outfit, sans-serif',
        position: 'relative',
      }}
    >
      {/* LEFT PANEL */}
      <section
        style={{
          flex: 1,
          minHeight: '100vh',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <img
          src="https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?w=1400&q=80"
          alt="Cybersecurity background"
          style={{
            position: 'absolute',
            inset: 0,
            width: '100%',
            height: '100%',
            objectFit: 'cover',
          }}
        />

        <div
          style={{
            position: 'absolute',
            inset: 0,
            background:
              'linear-gradient(90deg, rgba(3,8,18,0.28) 0%, rgba(3,8,18,0.34) 42%, rgba(3,8,18,0.52) 72%, rgba(3,8,18,0.72) 100%)',
          }}
        />

        <div
          style={{
            position: 'absolute',
            inset: 0,
            background:
              'linear-gradient(180deg, rgba(5,10,20,0.42) 0%, rgba(5,10,20,0.16) 32%, rgba(5,10,20,0.56) 100%)',
          }}
        />

        <div
          style={{
            position: 'relative',
            zIndex: 2,
            minHeight: '100vh',
            display: 'flex',
            alignItems: 'center',
            padding: '48px 54px',
            boxSizing: 'border-box',
          }}
        >
          <div
            style={{
              width: '100%',
              maxWidth: '700px',
              padding: '36px 34px',
              borderRadius: '28px',
              background: 'rgba(7, 16, 30, 0.45)',
              border: '1px solid rgba(148, 163, 184, 0.14)',
              backdropFilter: 'blur(10px)',
              boxShadow: '0 18px 50px rgba(0,0,0,0.28)',
              boxSizing: 'border-box',
            }}
          >
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '14px',
                marginBottom: '28px',
              }}
            >
              <div
                style={{
                  width: '50px',
                  height: '50px',
                  borderRadius: '15px',
                  background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: '0 0 26px rgba(6, 182, 212, 0.3)',
                }}
              >
                <svg
                  width="24"
                  height="24"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="white"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                </svg>
              </div>

              <span
                style={{
                  fontSize: '1.75rem',
                  fontWeight: 800,
                  background: 'linear-gradient(135deg, #67e8f9, #60a5fa)',
                  WebkitBackgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                }}
              >
                CyberShield
              </span>
            </div>

            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 14px',
                borderRadius: '999px',
                background: 'rgba(6,182,212,0.14)',
                border: '1px solid rgba(6,182,212,0.18)',
                color: '#67e8f9',
                fontSize: '0.82rem',
                fontWeight: 600,
                marginBottom: '18px',
              }}
            >
              <span
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  background: '#22d3ee',
                }}
              />

              Enterprise Security Access
            </div>

            <h1
              style={{
                fontSize: '3.8rem',
                fontWeight: 900,
                color: 'white',
                lineHeight: 1.03,
                margin: '0 0 18px',
                letterSpacing: '-0.05em',
              }}
            >
              Join the Threat
              <br />
              Intelligence Network
            </h1>

            <p
              style={{
                fontSize: '1.14rem',
                color: 'rgba(226, 232, 240, 0.9)',
                maxWidth: '540px',
                lineHeight: 1.7,
                margin: '0 0 28px',
              }}
            >
              Create your account to start protecting users, domains, and
              inboxes against phishing, malware, spoofing, and emerging cyber
              threats.
            </p>

            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(4, minmax(0, 1fr))',
                gap: '14px',
              }}
            >
              {[
                { value: '50K+', label: 'Threats Tracked' },
                { value: '99.2%', label: 'Detection Rate' },
                { value: '< 3s', label: 'Scan Time' },
                { value: '24/7', label: 'Monitoring' },
              ].map((item) => (
                <div
                  key={item.label}
                  style={{
                    padding: '18px',
                    borderRadius: '18px',
                    background: 'rgba(8, 15, 28, 0.52)',
                    border: '1px solid rgba(148, 163, 184, 0.1)',
                  }}
                >
                  <div
                    style={{
                      fontSize: '1.5rem',
                      fontWeight: 800,
                      color: 'white',
                      marginBottom: '4px',
                    }}
                  >
                    {item.value}
                  </div>

                  <div
                    style={{
                      fontSize: '0.78rem',
                      color: '#94a3b8',
                    }}
                  >
                    {item.label}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* RIGHT PANEL */}
      <section
        style={{
          width: '540px',
          minHeight: '100vh',
          flexShrink: 0,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '48px 56px',
          background: '#050b18',
          position: 'relative',
          zIndex: 2,
          boxSizing: 'border-box',
        }}
      >
        <div
          style={{
            position: 'absolute',
            left: '-80px',
            top: '-5%',
            width: '160px',
            height: '110%',
            background: '#050b18',
            transform: 'skewX(-4deg)',
            zIndex: 1,
            pointerEvents: 'none',
          }}
        />

        <div
          style={{
            width: '100%',
            maxWidth: '400px',
            position: 'relative',
            zIndex: 3,
          }}
        >
          <h2
            style={{
              fontSize: '2.3rem',
              fontWeight: 800,
              color: 'white',
              margin: '0 0 8px',
              letterSpacing: '-0.02em',
            }}
          >
            Sign Up Now
          </h2>

          <p
            style={{
              color: '#64748b',
              margin: '0 0 32px',
              fontSize: '1rem',
            }}
          >
            Start your threat intelligence journey
          </p>

          {error && (
            <div
              role="alert"
              style={{
                marginBottom: '20px',
                padding: '12px 16px',
                borderRadius: '12px',
                background: 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.25)',
              }}
            >
              <p
                style={{
                  color: '#ef4444',
                  fontSize: '0.9rem',
                  margin: 0,
                }}
              >
                {error}
              </p>
            </div>
          )}

          {success && (
            <div
              role="status"
              style={{
                marginBottom: '20px',
                padding: '12px 16px',
                borderRadius: '12px',
                background: 'rgba(34,197,94,0.08)',
                border: '1px solid rgba(34,197,94,0.25)',
              }}
            >
              <p
                style={{
                  color: '#4ade80',
                  fontSize: '0.9rem',
                  margin: 0,
                }}
              >
                {success}
              </p>
            </div>
          )}

          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '16px' }}>
              <label
                htmlFor="register-email"
                style={{
                  display: 'block',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#94a3b8',
                  marginBottom: '8px',
                }}
              >
                Email
              </label>

              <div style={{ position: 'relative' }}>
                <svg
                  style={{
                    position: 'absolute',
                    left: '16px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                  }}
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#4a5568"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z" />
                  <polyline points="22,6 12,13 2,6" />
                </svg>

                <input
                  id="register-email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleInputChange}
                  onFocus={focusInput}
                  onBlur={blurInput}
                  placeholder="you@company.com"
                  autoComplete="email"
                  required
                  disabled={loading}
                  style={inputStyle}
                />
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label
                htmlFor="register-username"
                style={{
                  display: 'block',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#94a3b8',
                  marginBottom: '8px',
                }}
              >
                Username
              </label>

              <div style={{ position: 'relative' }}>
                <svg
                  style={{
                    position: 'absolute',
                    left: '16px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                  }}
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#4a5568"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                  <circle cx="12" cy="7" r="4" />
                </svg>

                <input
                  id="register-username"
                  name="username"
                  type="text"
                  value={formData.username}
                  onChange={handleInputChange}
                  onFocus={focusInput}
                  onBlur={blurInput}
                  placeholder="Choose a username"
                  autoComplete="username"
                  required
                  disabled={loading}
                  style={inputStyle}
                />
              </div>
            </div>

            <div style={{ marginBottom: '16px' }}>
              <label
                htmlFor="register-password"
                style={{
                  display: 'block',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#94a3b8',
                  marginBottom: '8px',
                }}
              >
                Password
              </label>

              <div style={{ position: 'relative' }}>
                <svg
                  style={{
                    position: 'absolute',
                    left: '16px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                  }}
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#4a5568"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <rect x="3" y="11" width="18" height="11" rx="2" />
                  <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                </svg>

                <input
                  id="register-password"
                  name="password"
                  type="password"
                  value={formData.password}
                  onChange={handleInputChange}
                  onFocus={focusInput}
                  onBlur={blurInput}
                  placeholder="Minimum 8 characters"
                  autoComplete="new-password"
                  required
                  disabled={loading}
                  style={inputStyle}
                />
              </div>
            </div>

            <div style={{ marginBottom: '22px' }}>
              <label
                htmlFor="register-confirm-password"
                style={{
                  display: 'block',
                  fontSize: '0.85rem',
                  fontWeight: 600,
                  color: '#94a3b8',
                  marginBottom: '8px',
                }}
              >
                Confirm Password
              </label>

              <div style={{ position: 'relative' }}>
                <svg
                  style={{
                    position: 'absolute',
                    left: '16px',
                    top: '50%',
                    transform: 'translateY(-50%)',
                  }}
                  width="18"
                  height="18"
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="#4a5568"
                  strokeWidth="1.8"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                >
                  <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                  <polyline points="22 4 12 14.01 9 11.01" />
                </svg>

                <input
                  id="register-confirm-password"
                  name="confirmPassword"
                  type="password"
                  value={formData.confirmPassword}
                  onChange={handleInputChange}
                  onFocus={focusInput}
                  onBlur={blurInput}
                  placeholder="Confirm your password"
                  autoComplete="new-password"
                  required
                  disabled={loading}
                  style={inputStyle}
                />
              </div>
            </div>

            <label
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                cursor: 'pointer',
                marginBottom: '24px',
              }}
            >
              <input
                type="checkbox"
                checked={acceptedTerms}
                onChange={(event) => {
                  setAcceptedTerms(event.target.checked);
                  setError('');
                }}
                disabled={loading}
                style={{
                  accentColor: '#06b6d4',
                  width: '16px',
                  height: '16px',
                }}
              />

              <span
                style={{
                  fontSize: '0.85rem',
                  color: '#64748b',
                }}
              >
                I agree to the{' '}
                <span style={{ color: '#06b6d4' }}>
                  terms &amp; conditions
                </span>
              </span>
            </label>

            <button
              type="submit"
              disabled={loading}
              style={{
                width: '100%',
                padding: '16px',
                background: 'linear-gradient(135deg, #06b6d4, #3b82f6)',
                border: 'none',
                borderRadius: '12px',
                color: 'white',
                fontSize: '1rem',
                fontWeight: 700,
                cursor: loading ? 'not-allowed' : 'pointer',
                opacity: loading ? 0.6 : 1,
                boxShadow: '0 6px 24px rgba(6, 182, 212, 0.2)',
                fontFamily: 'Outfit, sans-serif',
              }}
            >
              {loading ? 'Creating account...' : 'Sign Up'}
            </button>
          </form>

          <div
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '16px',
              margin: '24px 0',
            }}
          >
            <div
              style={{
                flex: 1,
                height: '1px',
                background: '#1e293b',
              }}
            />

            <span
              style={{
                fontSize: '0.85rem',
                color: '#475569',
              }}
            >
              Or
            </span>

            <div
              style={{
                flex: 1,
                height: '1px',
                background: '#1e293b',
              }}
            />
          </div>

          <button
            type="button"
            onClick={() => {
              setError(
                'Google registration is not configured in the local environment.',
              );
            }}
            style={{
              width: '100%',
              padding: '14px',
              background: 'transparent',
              border: '1px solid #1e293b',
              borderRadius: '12px',
              color: '#94a3b8',
              fontSize: '0.95rem',
              fontWeight: 500,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '10px',
              fontFamily: 'Outfit, sans-serif',
            }}
          >
            <span
              style={{
                color: '#4285f4',
                fontSize: '1.1rem',
                fontWeight: 800,
              }}
            >
              G
            </span>

            Sign Up with Google
          </button>

          <p
            style={{
              textAlign: 'center',
              marginTop: '24px',
              fontSize: '0.95rem',
              color: '#64748b',
            }}
          >
            Already have an account?{' '}
            <Link
              to="/login"
              style={{
                color: '#06b6d4',
                fontWeight: 600,
                textDecoration: 'none',
              }}
            >
              Sign In
            </Link>
          </p>
        </div>
      </section>
    </div>
  );
}