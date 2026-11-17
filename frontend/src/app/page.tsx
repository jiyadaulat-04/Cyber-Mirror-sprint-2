"use client";

import { useCallback, useEffect, useState } from "react";

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

export default function Home() {
  const [simulations, setSimulations] = useState<Simulation[]>([]);
  const [events, setEvents] = useState<TelemetryEvent[]>([]);
  const [selectedSimulation, setSelectedSimulation] =
    useState<Simulation | null>(null);

  const [loading, setLoading] = useState(true);
  const [runningRedAI, setRunningRedAI] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  // Fetch simulations and telemetry
  const fetchDashboardData = useCallback(async () => {
    try {
      setError("");

      const simulationResponse = await fetch(
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

        const telemetryResponse = await fetch(
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
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : "Backend connection failed"
      );
    } finally {
      setLoading(false);
    }
  }, []);

  // Load dashboard data and enable automatic polling
  useEffect(() => {
    fetchDashboardData();

    const pollingInterval = window.setInterval(() => {
      fetchDashboardData();
    }, 5000);

    return () => {
      window.clearInterval(pollingInterval);
    };
  }, [fetchDashboardData]);

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

      const response = await fetch(
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
      value: "—",
      unit: "/100",
      status: "Not calculated yet",
      color: "text-emerald-400",
    },
    {
      label: "Total Simulations",
      value: String(simulations.length).padStart(2, "0"),
      unit: "",
      status: "From PostgreSQL",
      color: "text-blue-400",
    },
    {
      label: "Threats Detected",
      value: "—",
      unit: "",
      status: "Detection not implemented",
      color: "text-orange-400",
    },
    {
      label: "Telemetry Events",
      value: String(events.length),
      unit: "",
      status: "From PostgreSQL",
      color: "text-purple-400",
    },
  ];

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
            ["▦", "Dashboard"],
            ["◎", "Simulations"],
            ["⌘", "Arena"],
            ["◈", "Attack Memory"],
            ["⌁", "Telemetry Logs"],
            ["◉", "Security Reports"],
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

          <div className="flex items-center gap-3">
            <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs text-emerald-400">
              ● System Online
            </span>

            <div className="h-9 w-9 rounded-full bg-cyan-500/20 flex items-center justify-center text-cyan-400 font-bold">
              CM
            </div>
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
                    —
                  </span>

                  <span className="text-xs text-slate-400">
                    OUT OF 100
                  </span>

                </div>

              </div>

              <p className="text-center text-sm text-slate-400">
                Security scoring module pending
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
                    {runningRedAI ? "● Running" : "● Ready"}
                  </span>
                </div>

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

              </div>
            </div>
          </div>

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
                ↻ REFRESH
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
                          {event.payload.target || "—"}
                        </td>

                        <td className="py-4">
                          <span className="text-emerald-400">
                            ● {event.payload.status || "Logged"}
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
            CYBER MIRROR © 2026 | Autonomous Security Testing Platform
          </footer>

        </div>
      </section>
    </main>
  );
}