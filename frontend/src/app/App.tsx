import { useEffect, useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { AuthScreen } from "./components/AuthScreen";
import { CertificateVerification } from "./components/CertificateVerification";
import { RoleHome } from "./components/RoleHome";

export default function App() {
  const { session, login, registerCandidate, logout } = useAuth();
  const [showCertVerify, setShowCertVerify] = useState(false);

  // Shared accessibility toolkit state (Part 5), applied via document-level tokens.
  const [fontScale, setFontScale] = useState(1);
  const [highContrast, setHighContrast] = useState(false);

  useEffect(() => {
    document.documentElement.style.setProperty("--base-font-scale", String(fontScale));
    document.documentElement.classList.toggle("high-contrast", highContrast);
  }, [fontScale, highContrast]);

  // Public path first — certificate verification never requires login.
  if (showCertVerify && !session) {
    return <CertificateVerification onBack={() => setShowCertVerify(false)} />;
  }

  if (!session) {
    return (
      <AuthScreen
        onLogin={login}
        onRegister={registerCandidate}
        onVerifyCertificate={() => setShowCertVerify(true)}
      />
    );
  }

  return (
    <RoleHome
      session={session}
      onLogout={logout}
      fontScale={fontScale}
      setFontScale={setFontScale}
      highContrast={highContrast}
      setHighContrast={setHighContrast}
    />
  );
}
