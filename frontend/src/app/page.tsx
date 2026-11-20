"use client";

import { useCallback, useEffect, useState } from "react";
import AnalyticsDashboard from "./components/AnalyticsDashboard";

const API_URL = process.env.NEXT_PUBLIC_API_URL;

interface Simulation {
  id: number;
  name: string;
  status: string;
}

interface TelemetryEvent {
  id: number;
  simulation_id: number;
  event_type: string;
  source: string;
  payload: {
    target?: string;
    status?: string;
    [key: string]: unknown;
  };
}

interface AuthUser {
  id: number;
  username: string;
  role: "admin" | "analyst" | "viewer";
}

interface AnalyticsOverview {
  total_simulations: number;
  simulation_status: Record<string, number>;
  total_telemetry: number;
  red_ai_scans: number;
  threats_detected: number;
  blue_ai_actions: number;
  successful_mitigations: number;
  no_action_required: number;
  purple_ai_evaluations: number;
  average_security_score: number | null;
  valid_security_scores: number;
}

interface AnalyticsHistory {
  security_score_trend: {
    telemetry_id: number;
    simulation_id: number;
    timestamp: string;
    score: number;
    rating: string;
  }[];
  red_ai_history: {
    telemetry_id: number;
    simulation_id: number;
    timestamp: string;
    status: string;
    headers_present: number;
    headers_missing: number;
    http_status: number | null;
  }[];
  blue_ai_history: {
    telemetry_id: number;
    simulation_id: number;
    timestamp: string;
    status: string;
    mitigations_attempted: number;
    mitigations_successful: number;
  }[];
  recent_telemetry: {
    id: number;
    simulation_id: number;
    event_type: string;
    source: string;
    status: string;
    target: string | null;
    created_at: string | null;
  }[];
}
export default function Home() {
  const [simulations, setSimulations] = useState<Simulation[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [analyticsOverview, setAnalyticsOverview] =
    useState<AnalyticsOverview | null>(null);

  const [analyticsHistory, setAnalyticsHistory] =
    useState<AnalyticsHistory | null>(null);

  const [analyticsLoading, setAnalyticsLoading] = useState(true);
  const [analyticsError, setAnalyticsError] = useState("");

  const [selectedSimulation, setSelectedSimulation] =
    useState<Simulation | null>(null);

  const [loading, setLoading] = useState(true);
  const [runningRedAI, setRunningRedAI] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  // Authentication state
  const [token, setToken] = useState("");
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [authChecking, setAuthChecking] = useState(true);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loginError, setLoginError] = useState("");
  const [loginLoading, setLoginLoading] = useState(false);

  // Restore and validate an existing browser session
  useEffect(() => {
    const savedToken = sessionStorage.getItem("cyber_mirror_token");

    if (!savedToken) {
      setAuthChecking(false);
      return;
    }

    async function verifySession() {
      try {
        const response = await fetch(`${API_URL}/auth/me`, {
          headers: {
            Authorization: `Bearer ${savedToken}`,
          },
        });

        if (!response.ok) {
          throw new Error("Session expired");
        }

        const user: AuthUser = await response.json();

        setToken(savedToken ?? "");
        setCurrentUser(user);
      } catch {
        sessionStorage.removeItem("cyber_mirror_token");
        setToken("");
        setCurrentUser(null);
      } finally {
        setAuthChecking(false);
      }
    }

    verifySession();
  }, []);

  // Login using the FastAPI authentication endpoint
  async function handleLogin(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setLoginError("");
    setLoginLoading(true);

    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ username, password }),
      });

      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.detail || "Login failed");
      }

      sessionStorage.setItem("cyber_mirror_token", result.access_token);

      setToken(result.access_token);
      setCurrentUser(result.user);
      setPassword("");
    } catch (err) {
      setLoginError(
        err instanceof Error ? err.message : "Unable to login"
      );
    } finally {
      setLoginLoading(false);
    }
  }

  // Attach JWT to protected backend requests
  async function apiFetch(url: string, options: RequestInit = {}) {
    const response = await fetch(url, {
      ...options,
      headers: {
        ...options.headers,
        Authorization: `Bearer ${token}`,
      },
    });

    if (response.status === 401) {
      sessionStorage.removeItem("cyber_mirror_token");
      setToken("");
      setCurrentUser(null);
      throw new Error("Session expired. Please log in again.");
    }

    return response;
  }

  // Logout and clear the browser session
  function handleLogout() {
    sessionStorage.removeItem("cyber_mirror_token");
    setToken("");
    setCurrentUser(null);
    setSimulations([]);
    setEvents([]);
    setSelectedSimulation(null);
    setError("");
    setMessage("");
  }
  // Fetch simulations and telemetry
  const fetchDashboardData = useCallback(async () => {
    try {
      setError("");

      const simulationResponse = await apiFetch(
        `${API_URL}/simulations`
      );

      if (!simulationResponse.ok) {
        throw new Error("Unable to fetch simulations");
      }

      const simulationData: Simulation[] =
        await simulationResponse.json();

      setSimulations(simulationData);

      if (simulationData.length > 0) {
        const currentSimulation = simulationData[0];

        setSelectedSimulation(currentSimulation);

        const telemetryResponse = await apiFetch(
          `${API_URL}/simulations/${currentSimulation.id}/telemetry`
        );

        if (!telemetryResponse.ok) {
          throw new Error("Unable to fetch telemetry");
        }

        const telemetryData: TelemetryEvent[] =
          await telemetryResponse.json();

        setEvents(telemetryData.reverse());
      } else {
        setSelectedSimulation(null);
        setEvents([]);
      }
      // Fetch global analytics independently
      try {
        const [overviewResponse, historyResponse] = await Promise.all([
          apiFetch(`${API_URL}/analytics/overview`),
          apiFetch(`${API_URL}/analytics/history`)
        ]);

        if (!overviewResponse.ok || !historyResponse.ok) {
          throw new Error("Unable to fetch analytics data");
        }

        const overviewData: AnalyticsOverview =
          await overviewResponse.json();

        const historyData: AnalyticsHistory =
          await historyResponse.json();

        setAnalyticsOverview(overviewData);
        setAnalyticsHistory(historyData);
        setAnalyticsError("");
      } catch (analyticsErr) {
        setAnalyticsError(
          analyticsErr instanceof Error
            ? analyticsErr.message
            : "Unable to load analytics"
        );
      } finally {
        setAnalyticsLoading(false);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Backend connection failed"
      );
    } finally {
      setLoading(false);
    }
  }, [token]);

  // Load dashboard data and enable automatic polling
  useEffect(() => {
    if (!token) {
      return;
    }

    fetchDashboardData();

    const pollingInterval = window.setInterval(() => {
      fetchDashboardData();
    }, 5000);

    return () => {
      window.clearInterval(pollingInterval);
    };
  }, [fetchDashboardData, token]);

  // Run Red AI reconnaissance
  async function runRedAI() {
    if (!selectedSimulation) {
      setError("No simulation available");
      return;
    }

    try {
      setRunningRedAI(true);
      setError("");
      setMessage("");

      const response = await apiFetch(
        `${API_URL}/red-ai/run?simulation_id=${selectedSimulation.id}`,
        {
          method: "POST",
        }
      );

      if (!response.ok) {
        throw new Error("Red AI execution failed");
      }

      const result = await response.json();

      setMessage(
        `Red AI reconnaissance ${result.result.status}!`
      );

      await fetchDashboardData();
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Something went wrong"
      );
    } finally {
      setRunningRedAI(false);
    }
  }

  const stats = [
    {
      label: "Security Posture",
      value: analyticsOverview?.average_security_score != null
        ? analyticsOverview.average_security_score.toFixed(1)
        : "N/A",
      unit: "/100",
      status: `${analyticsOverview?.valid_security_scores ?? 0} valid evaluations`,
      color: "text-emerald-400",
    },
    {
      label: "Total Simulations",
      value: String(analyticsOverview?.total_simulations ?? 0).padStart(2, "0"),
      unit: "",
      status: "From PostgreSQL",
      color: "text-blue-400",
    },
    {
      label: "Threats Detected",
      value: String(analyticsOverview?.threats_detected ?? 0),
      unit: "",
      status: "Missing security headers",
      color: "text-orange-400",
    },
    {
      label: "Telemetry Events",
      value: String(analyticsOverview?.total_telemetry ?? 0),
      unit: "",
      status: "From PostgreSQL",
      color: "text-purple-400",
    },
  ];

  if (authChecking) {
    return (
      <main className="min-h-screen bg-[#080d19] flex items-center justify-center text-slate-200">
        <p className="text-cyan-400 text-sm">Verifying session...</p>
      </main>
    );
  }

  if (!token || !currentUser) {
  return (
      <main className="min-h-screen bg-[#080d19] flex items-center justify-center px-5 text-slate-200">
        <form onSubmit={handleLogin} className="w-full max-w-md rounded-2xl border border-slate-800 bg-[#0c1322] p-8 shadow-2xl">
          <div className="mb-8 text-center">
            <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-xl bg-cyan-500/10 text-xl font-bold text-cyan-400">CM</div>
            <h1 className="text-2xl font-bold text-white">Cyber Mirror</h1>
            <p className="mt-2 text-sm text-slate-400">Security Operations Center</p>
          </div>

          <div className="space-y-5">
            <div>
              <label htmlFor="username" className="mb-2 block text-sm text-slate-300">Username</label>
              <input id="username" type="text" autoComplete="username" required value={username} onChange={(event) => setUsername(event.target.value)} className="w-full rounded-lg border border-slate-700 bg-[#080d19] px-4 py-3 text-white outline-none focus:border-cyan-500" placeholder="Enter your username" />
            </div>

            <div>
              <label htmlFor="password" className="mb-2 block text-sm text-slate-300">Password</label>
              <input id="password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} className="w-full rounded-lg border border-slate-700 bg-[#080d19] px-4 py-3 text-white outline-none focus:border-cyan-500" placeholder="Enter your password" />
            </div>

            {loginError && <p role="alert" className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-sm text-red-400">{loginError}</p>}

            <button type="submit" disabled={loginLoading} className="w-full rounded-lg bg-cyan-500 px-4 py-3 font-semibold text-[#080d19] transition hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50">
              {loginLoading ? "Signing in..." : "Sign In"}
            </button>
          </div>
        </form>
      </main>
    );
  }
  const latestSecurityScore =
    analyticsHistory?.security_score_trend?.reduce<AnalyticsHistory["security_score_trend"][number] | null>(
      (latest, current) =>
        latest === null || current.telemetry_id > latest.telemetry_id
          ? current
          : latest,
      null as AnalyticsHistory["security_score_trend"][number] | null
    ) ?? null;

  return (
    <main className="min-h-screen bg-[#080d19] text-slate-200 flex">

      {/* Sidebar */}
      <aside className="hidden md:flex w-64 min-h-screen flex-col border-r border-slate-800 bg-[#0c1322] p-5">

        <div className="mb-10">
          <h1 className="text-2xl font-bold text-white">
            CYBER<span className="text-cyan-400">MIRROR</span>
          </h1>
          <p className="text-xs text-slate-500 mt-1">
            Autonomous Security Platform
          </p>
        </div>

        <p className="text-xs uppercase tracking-widest text-slate-500 mb-4">
          Workspace
        </p>

        <nav className="space-y-2">
          {[
            ["Ã¢â€“Â¦", "Dashboard"],
            ["Ã¢â€”Å½", "Simulations"],
            ["Ã¢Å’Ëœ", "Arena"],
            ["Ã¢â€”Ë†", "Attack Memory"],
            ["Ã¢Å’Â", "Telemetry Logs"],
            ["Ã¢â€”â€°", "Security Reports"],
          ].map(([icon, name], index) => (
            <div
              key={name}
              className={`flex items-center gap-3 rounded-lg px-4 py-3 text-sm ${
                index === 0
                  ? "bg-cyan-500/10 text-cyan-400 border border-cyan-500/20"
                  : "text-slate-400 hover:bg-slate-800"
              }`}
            >
              <span>{icon}</span>
              {name}
            </div>
          ))}
        </nav>

        <a
          href="http://localhost:8000/docs"
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 flex items-center gap-3 rounded-lg border border-cyan-500/20 bg-cyan-500/10 px-4 py-3 text-sm text-cyan-400 hover:bg-cyan-500/20 transition"
        >
          <span>🔌</span>
          API Explorer
          <span className="ml-auto">↗</span>
        </a>

        <div className="mt-auto border-t border-slate-800 pt-5">
          <p className="text-sm text-slate-400">System Status</p>

          <div className="flex items-center gap-2 mt-3">
            <span className="h-2 w-2 rounded-full bg-emerald-400"></span>
            <span className="text-xs text-emerald-400">
              Backend Connected
            </span>
          </div>
        </div>
      </aside>

      {/* Main Dashboard */}
      <section className="flex-1 min-w-0">

        {/* Header */}
        <header className="flex flex-wrap items-center justify-between gap-4 border-b border-slate-800 px-6 py-5">

          <div>
            <h2 className="text-xl font-semibold text-white">
              Security Operations Center
            </h2>

            <p className="text-sm text-slate-500 mt-1">
              Monitor and manage your security environment
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-3">
            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-400">
              System Online
            </span>

            <div className="text-right">
              <p className="text-sm font-medium text-white">
                {currentUser.username}
              </p>
              <p className="text-xs capitalize text-cyan-400">
                {currentUser.role}
              </p>
            </div>

            <button
              type="button"
              onClick={handleLogout}
              className="rounded-lg border border-slate-700 px-3 py-2 text-xs text-slate-300 transition hover:border-red-500 hover:text-red-400"
            >
              Logout
            </button>
          </div>
        </header>

        <div className="p-6">

          {/* Welcome */}
          <div className="mb-7">
            <p className="text-sm text-cyan-400 mb-2">
              SECURITY OVERVIEW
            </p>

            <h3 className="text-2xl font-bold text-white">
              Welcome to Cyber Mirror
            </h3>

            <p className="text-sm text-slate-400 mt-2">
              Your autonomous AI-powered security testing environment.
            </p>
          </div>

          {/* Error and Success Messages */}
          {error && (
            <div className="mb-5 rounded-lg border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
              {error}
            </div>
          )}

          {message && (
            <div className="mb-5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm text-emerald-400">
              {message}
            </div>
          )}

          {/* Statistics */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">

            {stats.map((stat) => (
              <div
                key={stat.label}
                className="rounded-xl border border-slate-800 bg-[#111a2b] p-5"
              >
                <p className="text-sm text-slate-400">
                  {stat.label}
                </p>

                <div className="flex items-baseline gap-1 mt-4">
                  <span className={`text-3xl font-bold ${stat.color}`}>
                    {loading ? "..." : stat.value}
                  </span>

                  <span className="text-sm text-slate-500">
                    {stat.unit}
                  </span>
                </div>

                <p className="text-xs text-slate-500 mt-3">
                  {stat.status}
                </p>
              </div>
            ))}

          </div>

          {/* Middle Section */}
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-5 mt-6">

            {/* Security Posture */}
            <div className="rounded-xl border border-slate-800 bg-[#111a2b] p-6">

              <h3 className="font-semibold text-white">
                Security Posture
              </h3>

              <p className="text-sm text-slate-500 mt-1">
                Overall environment security score
              </p>

              <div className="flex items-center justify-center py-8">

                <div className="h-40 w-40 rounded-full border-[12px] border-slate-700 flex flex-col items-center justify-center">

                  <span className="text-4xl font-bold text-white">
                    {latestSecurityScore?.score != null
                      ? Math.round(latestSecurityScore.score)
                      : "â€”"}
                  </span>

                  <span className="text-xs text-slate-400">
                    OUT OF 100
                  </span>

                </div>

              </div>

              <p className="text-center text-sm text-slate-400">
                {latestSecurityScore?.rating ?? "No evaluation yet"}
              </p>

            </div>

            {/* Simulation */}
            <div className="rounded-xl border border-slate-800 bg-[#111a2b] p-6">

              <h3 className="font-semibold text-white">
                Simulation
              </h3>

              <p className="text-sm text-slate-500 mt-1">
                Current Arena activity
              </p>

              <div className="mt-6 space-y-5">

                <div className="flex justify-between">
                  <span className="text-sm text-slate-400">
                    Simulation ID
                  </span>

                  <span className="text-sm text-white">
                    {selectedSimulation
                      ? `SIM-${String(selectedSimulation.id).padStart(3, "0")}`
                      : "Not available"}
                  </span>
                </div>

                <div className="flex justify-between gap-4">
                  <span className="text-sm text-slate-400">
                    Simulation Name
                  </span>

                  <span className="text-sm text-white text-right">
                    {selectedSimulation?.name || "No simulation"}
                  </span>
                </div>

                <div className="flex justify-between">
                  <span className="text-sm text-slate-400">
                    Simulation Status
                  </span>

                  <span className="text-sm text-cyan-400">
                    {selectedSimulation?.status || "Unavailable"}
                  </span>
                </div>

                <div className="flex justify-between">
                  <span className="text-sm text-slate-400">
                    Red AI Status
                  </span>

                  <span className="text-sm text-orange-400">
                    {runningRedAI ? "Ã¢â€”Â Running" : "Ã¢â€”Â Ready"}
                  </span>
                </div>

                {currentUser.role !== "viewer" && (
                  <div className="border-t border-slate-800 pt-4">

                    <button
                      onClick={runRedAI}
                    disabled={!selectedSimulation || runningRedAI}
                    className="w-full rounded-lg bg-cyan-500 px-4 py-3 text-sm font-semibold text-[#080d19] hover:bg-cyan-400 disabled:cursor-not-allowed disabled:opacity-50 transition"
                  >
                    {runningRedAI
                      ? "Running Reconnaissance..."
                      : "Run Red AI Reconnaissance"}
                    </button>

                  </div>
                )}

              </div>
            </div>
          </div>

          {/* Global Analytics Dashboard */}
          <AnalyticsDashboard
            overview={analyticsOverview}
            history={analyticsHistory}
            loading={analyticsLoading}
            error={analyticsError}
          />
          {/* Telemetry Table */}
          <div className="mt-6 rounded-xl border border-slate-800 bg-[#111a2b] p-6">

            <div className="flex flex-wrap justify-between gap-3 mb-5">

              <div>
                <h3 className="font-semibold text-white">
                  Recent Telemetry Events
                </h3>

                <p className="text-xs text-slate-500 mt-1">
                  Latest recorded security activities from PostgreSQL
                </p>
              </div>

              <button
                onClick={fetchDashboardData}
                className="text-xs text-cyan-400 hover:text-cyan-300"
              >
                Ã¢â€ Â» REFRESH
              </button>

            </div>

            <div className="overflow-x-auto">

              <table className="w-full text-left text-sm">

                <thead>
                  <tr className="border-b border-slate-800 text-xs text-slate-500">
                    <th className="py-3 pr-4">ID</th>
                    <th className="py-3 pr-4">EVENT</th>
                    <th className="py-3 pr-4">SOURCE</th>
                    <th className="py-3 pr-4">TARGET</th>
                    <th className="py-3">STATUS</th>
                  </tr>
                </thead>

                <tbody>

                  {loading ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-slate-500">
                        Loading telemetry...
                      </td>
                    </tr>
                  ) : events.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="py-6 text-center text-slate-500">
                        No telemetry events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    events.map((event) => (
                      <tr
                        key={event.id}
                        className="border-b border-slate-800/70 text-slate-300"
                      >

                        <td className="py-4 pr-4 text-slate-500">
                          #{event.id}
                        </td>

                        <td className="py-4 pr-4">
                          {event.event_type}
                        </td>

                        <td className="py-4 pr-4">
                          {event.source}
                        </td>

                        <td className="py-4 pr-4">
                          {event.payload.target || "Ã¢â‚¬â€"}
                        </td>

                        <td className="py-4">
                          <span className="text-emerald-400">
                            Ã¢â€”Â {event.payload.status || "Logged"}
                          </span>
                        </td>

                      </tr>
                    ))
                  )}

                </tbody>

              </table>

            </div>
          </div>

          <footer className="mt-8 text-center text-xs text-slate-600">
            CYBER MIRROR Ã‚Â© 2026 | Autonomous Security Testing Platform
          </footer>

        </div>
      </section>
    </main>
  );
}



