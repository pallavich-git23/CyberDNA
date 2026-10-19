
document.addEventListener("DOMContentLoaded", function () {
    const chartDataElement = document.getElementById("chart-data");

    // Check if chart data exists
    if (!chartDataElement) {
        console.error("CyberDNA: Chart data not found.");
        return;
    }

    // Check if Chart.js is loaded
    if (typeof Chart === "undefined") {
        console.error("CyberDNA: Chart.js is not loaded.");
        return;
    }

    // Read chart data from the dashboard
    let chartData;

    try {
        chartData = JSON.parse(chartDataElement.textContent);
    } catch (error) {
        console.error("CyberDNA: Invalid chart data.", error);
        return;
    }

    // Threat severity counts
    const highCount = Number(chartData.high) || 0;
    const mediumCount = Number(chartData.medium) || 0;
    const lowCount = Number(chartData.low) || 0;

    // Daily scan activity data
    const activityLabels = Array.isArray(chartData.days)
        ? chartData.days
        : [];

    const activityValues = Array.isArray(chartData.totals)
        ? chartData.totals.map(function (value) {
            return Number(value) || 0;
        })
        : [];

    // =========================================
    // THREAT SEVERITY DOUGHNUT CHART
    // =========================================

    const severityCanvas = document.getElementById("severityChart");

    if (severityCanvas) {
        const oldSeverityChart = Chart.getChart(severityCanvas);

        if (oldSeverityChart) {
            oldSeverityChart.destroy();
        }

        new Chart(severityCanvas, {
            type: "doughnut",

            data: {
                labels: [
                    "High Risk",
                    "Medium Risk",
                    "Low Risk"
                ],

                datasets: [
                    {
                        label: "Threat Severity",

                        data: [
                            highCount,
                            mediumCount,
                            lowCount
                        ],

                        backgroundColor: [
                            "#ff5d72",
                            "#f6b94a",
                            "#2ed6a1"
                        ],

                        borderWidth: 0,
                        hoverOffset: 6
                    }
                ]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: "76%",

                plugins: {
                    legend: {
                        display: false
                    },

                    tooltip: {
                        enabled: true
                    }
                }
            }
        });
    }

    // =========================================
    // DAILY SCAN ACTIVITY LINE CHART
    // =========================================

    const activityCanvas = document.getElementById("activityChart");

    if (activityCanvas) {
        const oldActivityChart = Chart.getChart(activityCanvas);

        if (oldActivityChart) {
            oldActivityChart.destroy();
        }

        new Chart(activityCanvas, {
            type: "line",

            data: {
                labels: activityLabels,

                datasets: [
                    {
                        label: "Scans",

                        data: activityValues,

                        borderColor: "#35c8ee",

                        backgroundColor: "rgba(53, 200, 238, 0.12)",

                        fill: true,
                        tension: 0.38,
                        borderWidth: 2,

                        pointRadius: 4,
                        pointHoverRadius: 7,

                        pointBackgroundColor: "#35c8ee",
                        pointBorderColor: "#0b1422",
                        pointBorderWidth: 2
                    }
                ]
            },

            options: {
                responsive: true,
                maintainAspectRatio: false,

                interaction: {
                    intersect: false,
                    mode: "index"
                },

                plugins: {
                    legend: {
                        display: false
                    },

                    tooltip: {
                        enabled: true
                    }
                },

                scales: {
                    x: {
                        grid: {
                            display: false
                        },

                        ticks: {
                            color: "#7f91ac",
                            maxRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: 7
                        }
                    },

                    y: {
                        beginAtZero: true,
                        grace: "10%",

                        grid: {
                            color: "rgba(132, 153, 181, 0.12)"
                        },

                        ticks: {
                            color: "#7f91ac",
                            precision: 0
                        }
                    }
                }
            }
        });
    }

    // =========================================
    // DEBUG INFORMATION
    // =========================================

    console.log("CyberDNA charts loaded successfully.");

    console.log("Threat severity counts:", {
        high: highCount,
        medium: mediumCount,
        low: lowCount
    });

    console.log("Daily scan activity:", {
        dates: activityLabels,
        totals: activityValues
    });
});
