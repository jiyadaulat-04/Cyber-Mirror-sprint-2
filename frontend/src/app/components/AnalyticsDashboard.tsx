"use client";

import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  Legend
} from "recharts";

interface AnalyticsOverview {
  total_simulations: number;
  simulation_status: Record<string, number>;
  total_telemetry: number;
  red_ai_scans: number;
  blue_ai_actions: number;
  successful_mitigations: number;
  no_action_required: number;
  purple_ai_evaluations: number;
  average_security_score: number | null;
  valid_security_scores: number;
}

interface ScoreRecord {
  telemetry_id: number;
  simulation_id: number;
  timestamp: string;
  score: number;
  rating: string;
}

interface RedRecord {
  telemetry_id: number;
  simulation_id: number;
  timestamp: string;
  status: string;
  headers_present: number;
  headers_missing: number;
  http_status: number | null;
}

interface BlueRecord {
  telemetry_id: number;
  simulation_id: number;
  timestamp: string;
  status: string;
  mitigations_attempted: number;
  mitigations_successful: number;
}

interface TelemetryRecord {
  id: number;
  simulation_id: number;
  event_type: string;
  source: string;
  status: string;
  target: string | null;
  created_at: string | null;
}

interface AnalyticsHistory {
  security_score_trend: ScoreRecord[];
  red_ai_history: RedRecord[];
  blue_ai_history: BlueRecord[];
  recent_telemetry: TelemetryRecord[];
}

interface Props {
  overview: AnalyticsOverview | null;
  history: AnalyticsHistory | null;
  loading: boolean;
  error: string;
}

const panel =
  "rounded-xl border border-slate-800 bg-[#111a2b] p-5";

const tooltipStyle = {
  backgroundColor: "#0c1322",
  border: "1px solid #334155",
  borderRadius: "8px",
  color: "#e2e8f0"
};

function formatTime(value: string) {
  return new Date(value).toLocaleString();
}

export default function AnalyticsDashboard({
  overview,
  history,
  loading,
  error
}: Props) {
  if (loading && !overview) {
    return (
      <div className={panel + " mt-6 text-center text-slate-400"}>
        Loading analytics from PostgreSQL...
      </div>
    );
  }

  if (error && !overview) {
    return (
      <div className={panel + " mt-6 text-center text-red-400"}>
        Analytics unavailable: {error}
      </div>
    );
  }

  if (!overview || !history) {
    return (
      <div className={panel + " mt-6 text-center text-slate-400"}>
        No analytics data available.
      </div>
    );
  }

  const scoreData = history.security_score_trend.map((item) => ({
    ...item,
    label: formatTime(item.timestamp)
  }));

  const redData = history.red_ai_history.map((item) => ({
    ...item,
    label: `Scan #${item.telemetry_id}`
  }));

  const blueData = history.blue_ai_history.map((item) => ({
    ...item,
    label: `Event #${item.telemetry_id}`
  }));

  const statusData = Object.entries(
    overview.simulation_status
  ).map(([name, value]) => ({
    name,
    value
  }));

  const summaryCards = [
    {
      label: "Total Simulations",
      value: overview.total_simulations,
      color: "text-blue-400"
    },
    {
      label: "Average Security Score",
      value:
        overview.average_security_score === null
          ? "N/A"
          : `${overview.average_security_score}/100`,
      color: "text-emerald-400"
    },
    {
      label: "Red AI Scans",
      value: overview.red_ai_scans,
      color: "text-orange-400"
    },
    {
      label: "Telemetry Events",
      value: overview.total_telemetry,
      color: "text-purple-400"
    }
  ];

  return (
    <section className="mt-8 space-y-6">

      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <p className="text-xs font-semibold tracking-widest text-cyan-400">
            SECURITY INTELLIGENCE
          </p>
          <h2 className="mt-1 text-xl font-bold text-white">
            Analytics Dashboard
          </h2>
          <p className="mt-1 text-xs text-slate-500">
            Historical analytics from all simulations
          </p>
        </div>

        <span className="rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs text-emerald-400">
          PostgreSQL Connected
        </span>
      </div>

      {error && (
        <div className="rounded-lg border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm text-yellow-400">
          Analytics refresh warning: {error}
        </div>
      )}

      {/* Summary cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {summaryCards.map((card) => (
          <div key={card.label} className={panel}>
            <p className="text-sm text-slate-400">
              {card.label}
            </p>
            <p className={`mt-4 text-3xl font-bold ${card.color}`}>
              {card.value}
            </p>
          </div>
        ))}
      </div>

      {/* Simulation status and Purple AI */}
      <div className="grid grid-cols-1 gap-5 xl:grid-cols-2">

        <div className={panel}>
          <h3 className="font-semibold text-white">
            Simulation Status Overview
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            Distribution of simulation lifecycle states
          </p>

          {statusData.every((item) => item.value === 0) ? (
            <p className="py-16 text-center text-sm text-slate-500">
              No simulation records available.
            </p>
          ) : (
            <div className="mt-5 h-72">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={statusData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={95}
                    label
                  >
                    {statusData.map((item, index) => (
                      <Cell
                        key={item.name}
                        fill={[
                          "#06b6d4",
                          "#3b82f6",
                          "#a78bfa",
                          "#10b981",
                          "#f97316",
                          "#ef4444"
                        ][index % 6]}
                      />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </div>

        <div className={panel}>
          <h3 className="font-semibold text-white">
            Purple AI Security Score Trend
          </h3>
          <p className="mt-1 text-xs text-slate-500">
            Recorded security scores across simulations
          </p>

          {scoreData.length === 0 ? (
            <p className="py-16 text-center text-sm text-slate-500">
              No Purple AI evaluations recorded yet.
            </p>
          ) : (
            <div className="mt-5 h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={scoreData}>
                  <CartesianGrid
                    strokeDasharray="3 3"
                    stroke="#334155"
                  />
                  <XAxis
                    dataKey="telemetry_id"
                    stroke="#94a3b8"
                    tick={{ fontSize: 11 }}
                  />
                  <YAxis
                    domain={[0, 100]}
                    stroke="#94a3b8"
                  />
                  <Tooltip
                    contentStyle={tooltipStyle}
                    labelFormatter={(value) => `Telemetry #${value}`}
                  />
                  <Line
                    type="monotone"
                    dataKey="score"
                    stroke="#10b981"
                    strokeWidth={3}
                    dot={{ r: 4 }}
                    activeDot={{ r: 7 }}
                    name="Security Score"
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}

          <p className="mt-3 text-xs text-slate-500">
            {overview.valid_security_scores} valid evaluations.
            Scores evaluate security headers only.
          </p>
        </div>

      </div>

      {/* Red AI */}
      <div className={panel}>
        <h3 className="font-semibold text-white">
          Red AI Reconnaissance Analytics
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          Security headers detected during HTTP reconnaissance
        </p>

        {redData.length === 0 ? (
          <p className="py-16 text-center text-sm text-slate-500">
            No reconnaissance history available.
          </p>
        ) : (
          <div className="mt-5 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={redData}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#334155"
                />
                <XAxis dataKey="label" stroke="#94a3b8" />
                <YAxis allowDecimals={false} stroke="#94a3b8" />
                <Tooltip contentStyle={tooltipStyle} />
                <Legend />
                <Bar
                  dataKey="headers_present"
                  name="Headers Present"
                  fill="#10b981"
                />
                <Bar
                  dataKey="headers_missing"
                  name="Headers Missing"
                  fill="#ef4444"
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </div>

      {/* Blue AI */}
      <div className={panel}>
        <h3 className="font-semibold text-white">
          Blue AI Mitigation Analytics
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          Attempted and successfully applied header mitigations
        </p>

        {blueData.length === 0 ? (
          <p className="py-16 text-center text-sm text-slate-500">
            No mitigation history available.
          </p>
        ) : (
          <div className="mt-5 h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={blueData}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke="#334155"
                />
                <XAxis dataKey="label" stroke="#94a3b8" />
                <YAxis allowDecimals={false} stroke="#94a3b8" />
                <Tooltip contentStyle={tooltipStyle} />
                <Legend />
                <Bar
                  dataKey="mitigations_attempted"
                  name="Attempted"
                  fill="#f97316"
                />
                <Bar
                  dataKey="mitigations_successful"
                  name="Successful"
                  fill="#10b981"
                />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        <div className="mt-4 grid grid-cols-2 gap-4 border-t border-slate-800 pt-4">
          <div>
            <p className="text-xs text-slate-500">
              Successful individual mitigations
            </p>
            <p className="mt-1 text-2xl font-bold text-emerald-400">
              {overview.successful_mitigations}
            </p>
          </div>
          <div>
            <p className="text-xs text-slate-500">
              No action required events
            </p>
            <p className="mt-1 text-2xl font-bold text-cyan-400">
              {overview.no_action_required}
            </p>
          </div>
        </div>
      </div>

      {/* Recent telemetry */}
      <div className={panel}>
        <h3 className="font-semibold text-white">
          Global Telemetry History
        </h3>
        <p className="mt-1 text-xs text-slate-500">
          Latest 20 events across all simulations
        </p>

        {history.recent_telemetry.length === 0 ? (
          <p className="py-10 text-center text-sm text-slate-500">
            No telemetry events recorded.
          </p>
        ) : (
          <div className="mt-5 overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-xs text-slate-500">
                  <th className="py-3 pr-4">ID</th>
                  <th className="py-3 pr-4">SIMULATION</th>
                  <th className="py-3 pr-4">SOURCE</th>
                  <th className="py-3 pr-4">EVENT</th>
                  <th className="py-3 pr-4">STATUS</th>
                  <th className="py-3">TIMESTAMP</th>
                </tr>
              </thead>

              <tbody>
                {history.recent_telemetry.map((event) => (
                  <tr
                    key={event.id}
                    className="border-b border-slate-800/70 text-slate-300"
                  >
                    <td className="py-3 pr-4 text-slate-500">
                      #{event.id}
                    </td>
                    <td className="py-3 pr-4">
                      SIM-{String(event.simulation_id).padStart(3, "0")}
                    </td>
                    <td className="py-3 pr-4">
                      {event.source}
                    </td>
                    <td className="py-3 pr-4">
                      {event.event_type}
                    </td>
                    <td className="py-3 pr-4 text-cyan-400">
                      {event.status}
                    </td>
                    <td className="py-3 text-xs text-slate-500">
                      {event.created_at
                        ? formatTime(event.created_at)
                        : "Unavailable"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <p className="text-center text-xs text-slate-600">
        Analytics are based on recorded security-header checks and telemetry.
        They do not represent comprehensive vulnerability detection.
      </p>

    </section>
  );
}
