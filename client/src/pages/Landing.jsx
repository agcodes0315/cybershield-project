import { Link } from 'react-router-dom';
import {
  Activity,
  ArrowRight,
  BadgeCheck,
  Blocks,
  Bot,
  Braces,
  CheckCircle2,
  Cloud,
  Code2,
  Database,
  ExternalLink,
  FileSearch,
  Github,
  Globe2,
  KeyRound,
  LockKeyhole,
  MailWarning,
  Network,
  Radar,
  ScanSearch,
  Server,
  Shield,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Workflow,
} from 'lucide-react';

import './Landing.css';

const features = [
  {
    icon: ScanSearch,
    title: 'Phishing URL Detection',
    description:
      'Analyze suspicious links using lexical URL features, reputation intelligence, SSL checks, and machine-learning-assisted classification.',
  },
  {
    icon: MailWarning,
    title: 'Email Threat Analysis',
    description:
      'Inspect SPF, DKIM, DMARC, sender identity, suspicious headers, and spoofing indicators from one security workflow.',
  },
  {
    icon: Network,
    title: 'Network Reconnaissance',
    description:
      'Perform controlled reconnaissance, inspect exposed services, and organize findings for security investigation.',
  },
  {
    icon: Radar,
    title: 'Threat Intelligence',
    description:
      'Enrich investigations with security signals, reputation sources, breach intelligence, and community-driven reports.',
  },
  {
    icon: FileSearch,
    title: 'YARA and File Analysis',
    description:
      'Evaluate suspicious content against detection rules and present readable evidence for analyst review.',
  },
  {
    icon: ShieldCheck,
    title: 'Audit and Access Control',
    description:
      'Protect workflows with JWT authentication, role-aware access, persistent records, and auditable security actions.',
  },
];

const proofPoints = [
  {
    icon: Cloud,
    value: 'Azure',
    label: 'Real cloud deployment',
  },
  {
    icon: Blocks,
    value: '3 Services',
    label: 'Independently deployed architecture',
  },
  {
    icon: Braces,
    value: '20 Features',
    label: 'URL lexical feature pipeline',
  },
  {
    icon: KeyRound,
    value: 'JWT Auth',
    label: 'Authenticated application access',
  },
  {
    icon: Database,
    value: 'PostgreSQL',
    label: 'Persistent production database',
  },
  {
    icon: Server,
    value: 'Containers',
    label: 'Dockerized backend services',
  },
];

const stack = [
  'React',
  'Node.js',
  'Express',
  'FastAPI',
  'PostgreSQL',
  'Redis',
  'Docker',
  'Azure',
  'JWT',
  'scikit-learn',
];

const architectureNodes = [
  {
    icon: Globe2,
    label: 'Frontend',
    title: 'React Application',
    detail: 'Azure Static Web Apps',
  },
  {
    icon: Workflow,
    label: 'Gateway',
    title: 'Express API Gateway',
    detail: 'Authentication and orchestration',
  },
  {
    icon: Bot,
    label: 'Intelligence',
    title: 'FastAPI Detection Engine',
    detail: 'Detection and enrichment workflows',
  },
  {
    icon: Database,
    label: 'Data Layer',
    title: 'PostgreSQL and Redis',
    detail: 'Persistence and fast-access data',
  },
];

const productionChecks = [
  'Frontend deployed on Azure Static Web Apps',
  'API Gateway deployed on Azure Container Apps',
  'Detection Engine deployed as a separate service',
  'Managed PostgreSQL database hosted on Azure',
  'HTTPS communication between public services',
  'Environment-based frontend API configuration',
];

function ShieldLogo() {
  return (
    <div className="landing-logo-mark" aria-hidden="true">
      <Shield size={24} strokeWidth={2.4} />
    </div>
  );
}

export default function Landing() {
  const year = new Date().getFullYear();

  return (
    <div className="landing-page">
      <header className="landing-header">
        <div className="landing-container landing-nav">
          <Link to="/" className="landing-brand" aria-label="CyberShield home">
            <ShieldLogo />

            <div>
              <span className="landing-brand-name">CyberShield</span>
              <span className="landing-brand-tagline">
                Threat Intelligence Platform
              </span>
            </div>
          </Link>

          <nav className="landing-nav-links" aria-label="Primary navigation">
            <a href="#features">Capabilities</a>
            <a href="#architecture">Architecture</a>
            <a href="#production">Deployment</a>
            <a href="#technology">Technology</a>
          </nav>

          <div className="landing-nav-actions">
            <Link to="/login" className="landing-button landing-button-ghost">
              Sign in
            </Link>

            <Link to="/register" className="landing-button landing-button-small">
              Explore platform
              <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </header>

      <main>
        <section className="landing-hero">
          <div className="landing-grid-background" />

          <div className="landing-glow landing-glow-one" />
          <div className="landing-glow landing-glow-two" />

          <div className="landing-container landing-hero-grid">
            <div className="landing-hero-copy">
              <div className="landing-eyebrow">
                <span className="landing-live-dot" />
                Deployed on Microsoft Azure
              </div>

              <h1>
                Investigate cyber threats with
                <span> intelligence, context, and control.</span>
              </h1>

              <p className="landing-hero-description">
                CyberShield is a cloud-deployed cyber threat intelligence
                platform for phishing detection, suspicious email analysis,
                reconnaissance, breach intelligence, and security
                investigation.
              </p>

              <div className="landing-hero-actions">
                <Link to="/register" className="landing-button landing-button-primary">
                  Open live platform
                  <ArrowRight size={18} />
                </Link>

                <a
                  href="#architecture"
                  className="landing-button landing-button-secondary"
                >
                  View architecture
                  <Blocks size={18} />
                </a>

                <a
                  href="https://github.com/agrima150103"
                  target="_blank"
                  rel="noreferrer"
                  className="landing-button landing-button-text"
                >
                  <Github size={18} />
                  GitHub
                </a>
              </div>

              <div className="landing-hero-trust">
                <div>
                  <CheckCircle2 size={17} />
                  Production cloud deployment
                </div>

                <div>
                  <CheckCircle2 size={17} />
                  Multi-service architecture
                </div>

                <div>
                  <CheckCircle2 size={17} />
                  Authenticated workflows
                </div>
              </div>
            </div>

            <div className="landing-console">
              <div className="landing-console-topbar">
                <div className="landing-console-dots">
                  <span />
                  <span />
                  <span />
                </div>

                <div className="landing-console-title">
                  <TerminalSquare size={15} />
                  investigation-session
                </div>

                <div className="landing-console-status">
                  <span />
                  Live
                </div>
              </div>

              <div className="landing-console-content">
                <div className="landing-console-command">
                  <span>cybershield</span>
                  <span className="landing-console-muted">/ analyze</span>
                </div>

                <div className="landing-risk-panel">
                  <div className="landing-risk-heading">
                    <div>
                      <span className="landing-panel-kicker">
                        Threat assessment
                      </span>
                      <h3>Suspicious URL detected</h3>
                    </div>

                    <div className="landing-risk-badge">High risk</div>
                  </div>

                  <div className="landing-risk-url">
                    <LockKeyhole size={16} />
                    secure-account-verification.example
                  </div>

                  <div className="landing-risk-grid">
                    <div>
                      <span>Lexical indicators</span>
                      <strong>Flagged</strong>
                    </div>

                    <div>
                      <span>Domain reputation</span>
                      <strong>Suspicious</strong>
                    </div>

                    <div>
                      <span>SSL assessment</span>
                      <strong>Reviewed</strong>
                    </div>

                    <div>
                      <span>Threat enrichment</span>
                      <strong>Complete</strong>
                    </div>
                  </div>
                </div>

                <div className="landing-activity-list">
                  <div className="landing-activity-item">
                    <div className="landing-activity-icon">
                      <Activity size={17} />
                    </div>

                    <div>
                      <strong>Detection pipeline completed</strong>
                      <span>Signals normalized and evaluated</span>
                    </div>

                    <BadgeCheck size={18} />
                  </div>

                  <div className="landing-activity-item">
                    <div className="landing-activity-icon">
                      <Database size={17} />
                    </div>

                    <div>
                      <strong>Investigation persisted</strong>
                      <span>Result stored in PostgreSQL</span>
                    </div>

                    <BadgeCheck size={18} />
                  </div>

                  <div className="landing-activity-item">
                    <div className="landing-activity-icon">
                      <ShieldCheck size={17} />
                    </div>

                    <div>
                      <strong>Audit event recorded</strong>
                      <span>Authenticated action captured</span>
                    </div>

                    <BadgeCheck size={18} />
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section className="landing-proof-strip" aria-label="Project proof points">
          <div className="landing-container landing-proof-grid">
            {proofPoints.map((item) => {
              const Icon = item.icon;

              return (
                <article className="landing-proof-item" key={item.label}>
                  <Icon size={21} />

                  <div>
                    <strong>{item.value}</strong>
                    <span>{item.label}</span>
                  </div>
                </article>
              );
            })}
          </div>
        </section>

        <section id="features" className="landing-section">
          <div className="landing-container">
            <div className="landing-section-heading">
              <div>
                <span className="landing-section-kicker">
                  Security capabilities
                </span>

                <h2>One platform for practical threat investigation.</h2>
              </div>

              <p>
                CyberShield combines detection, enrichment, investigation, and
                audit workflows so suspicious activity can be examined from a
                unified interface.
              </p>
            </div>

            <div className="landing-feature-grid">
              {features.map((feature) => {
                const Icon = feature.icon;

                return (
                  <article className="landing-feature-card" key={feature.title}>
                    <div className="landing-feature-icon">
                      <Icon size={23} />
                    </div>

                    <h3>{feature.title}</h3>
                    <p>{feature.description}</p>

                    <div className="landing-feature-link">
                      Included in platform
                      <CheckCircle2 size={16} />
                    </div>
                  </article>
                );
              })}
            </div>
          </div>
        </section>

        <section id="architecture" className="landing-section landing-section-dark">
          <div className="landing-container">
            <div className="landing-section-heading">
              <div>
                <span className="landing-section-kicker">
                  System architecture
                </span>

                <h2>Designed as independently deployable services.</h2>
              </div>

              <p>
                The user interface, gateway, detection engine, and data layer
                are separated to make the system easier to deploy, monitor,
                maintain, and scale.
              </p>
            </div>

            <div className="landing-architecture">
              {architectureNodes.map((node, index) => {
                const Icon = node.icon;

                return (
                  <div className="landing-architecture-step" key={node.title}>
                    <article className="landing-architecture-card">
                      <div className="landing-architecture-icon">
                        <Icon size={24} />
                      </div>

                      <span>{node.label}</span>
                      <h3>{node.title}</h3>
                      <p>{node.detail}</p>
                    </article>

                    {index < architectureNodes.length - 1 && (
                      <div className="landing-architecture-arrow">
                        <ArrowRight size={22} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>

            <div className="landing-architecture-note">
              <Sparkles size={19} />

              <p>
                This separation allows the React frontend, Express gateway, and
                FastAPI detection service to be deployed and updated
                independently.
              </p>
            </div>
          </div>
        </section>

        <section id="production" className="landing-section">
          <div className="landing-container landing-production-grid">
            <div className="landing-production-copy">
              <span className="landing-section-kicker">
                Production deployment
              </span>

              <h2>Built beyond localhost.</h2>

              <p>
                CyberShield runs across real Azure services rather than a
                single local development process. The frontend communicates
                with separately deployed backend services using production
                environment configuration.
              </p>

              <div className="landing-production-actions">
                <Link to="/login" className="landing-button landing-button-primary">
                  Sign in to the platform
                  <ArrowRight size={18} />
                </Link>

                <a
                  href="https://cybershield-api-gateway.niceforest-87cbfff3.centralindia.azurecontainerapps.io/health"
                  target="_blank"
                  rel="noreferrer"
                  className="landing-button landing-button-secondary"
                >
                  API health
                  <ExternalLink size={17} />
                </a>
              </div>
            </div>

            <div className="landing-production-card">
              <div className="landing-production-card-heading">
                <div className="landing-production-icon">
                  <Cloud size={24} />
                </div>

                <div>
                  <span>Azure deployment</span>
                  <h3>Production environment</h3>
                </div>
              </div>

              <div className="landing-production-checks">
                {productionChecks.map((item) => (
                  <div key={item}>
                    <CheckCircle2 size={18} />
                    <span>{item}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section id="technology" className="landing-section landing-section-compact">
          <div className="landing-container">
            <div className="landing-technology-card">
              <div>
                <span className="landing-section-kicker">
                  Technology stack
                </span>

                <h2>Modern full-stack and cloud engineering.</h2>
              </div>

              <div className="landing-stack-list">
                {stack.map((technology) => (
                  <span key={technology}>{technology}</span>
                ))}
              </div>
            </div>
          </div>
        </section>

        <section className="landing-cta-section">
          <div className="landing-container">
            <div className="landing-cta-card">
              <div className="landing-cta-icon">
                <Shield size={31} />
              </div>

              <span className="landing-section-kicker">
                Explore the live system
              </span>

              <h2>See the complete CyberShield workflow.</h2>

              <p>
                Create an account, sign in, and explore phishing analysis,
                email investigation, reconnaissance, breach intelligence, and
                security operations modules.
              </p>

              <div className="landing-cta-actions">
                <Link to="/register" className="landing-button landing-button-primary">
                  Create an account
                  <ArrowRight size={18} />
                </Link>

                <Link to="/login" className="landing-button landing-button-secondary">
                  Sign in
                </Link>
              </div>
            </div>
          </div>
        </section>
      </main>

      <footer className="landing-footer">
        <div className="landing-container landing-footer-content">
          <div className="landing-footer-brand">
            <ShieldLogo />

            <div>
              <strong>CyberShield</strong>
              <span>Cloud-deployed cyber threat intelligence platform.</span>
            </div>
          </div>

          <div className="landing-footer-links">
            <a href="#features">Capabilities</a>
            <a href="#architecture">Architecture</a>
            <a href="#production">Deployment</a>
            <a
              href="https://github.com/agrima150103"
              target="_blank"
              rel="noreferrer"
            >
              GitHub
            </a>
          </div>

          <p>© {year} CyberShield. Built as an engineering portfolio project.</p>
        </div>
      </footer>
    </div>
  );
}