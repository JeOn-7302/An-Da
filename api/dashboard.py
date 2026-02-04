"""
경찰용 대시보드 API
피싱 탐지 현황 시각화 및 모니터링
"""

from fastapi import APIRouter
from fastapi.responses import HTMLResponse

from src.database import get_database

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/", response_class=HTMLResponse)
async def dashboard_page():
    """경찰용 피싱 탐지 대시보드 (시각화)"""
    db = get_database()
    stats = db.get_statistics()
    phishing_cases = db.get_phishing_cases(limit=20)

    # 브랜드별 통계 데이터 준비
    brand_labels = [b["brand"] for b in stats["brand_statistics"]]
    brand_counts = [b["count"] for b in stats["brand_statistics"]]

    # 일별 통계 데이터 준비
    daily_dates = [d["date"] for d in stats["daily_statistics"]]
    daily_totals = [d["total"] for d in stats["daily_statistics"]]
    daily_phishing = [d["phishing"] for d in stats["daily_statistics"]]

    # 케이스 테이블 HTML 생성
    cases_html = ""
    for case in phishing_cases:
        cases_html += f"""
        <tr>
            <td>{case.get('id', '-')}</td>
            <td><span class="badge badge-danger">{case.get('impersonated_brand', '-')}</span></td>
            <td class="url-cell" title="{case.get('url', '')}">{case.get('domain', '-')}</td>
            <td>{case.get('domain_created_date', '조회 불가')}</td>
            <td><span class="risk-score">{(case.get('risk_score', 0) * 100):.1f}%</span></td>
            <td class="reason-cell">{case.get('ai_reasoning', '-')[:100]}...</td>
            <td>{case.get('created_at', '-')[:10] if case.get('created_at') else '-'}</td>
        </tr>
        """

    html_content = f"""
    <!DOCTYPE html>
    <html lang="ko">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>안다(An-Da) - 피싱 탐지 대시보드</title>
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
                color: #e8e8e8;
                min-height: 100vh;
                padding: 20px;
            }}
            .header {{
                text-align: center;
                padding: 30px 0;
                border-bottom: 2px solid #0f3460;
                margin-bottom: 30px;
            }}
            .header h1 {{
                font-size: 2.5em;
                color: #00d4ff;
                text-shadow: 0 0 20px rgba(0, 212, 255, 0.5);
            }}
            .header p {{
                color: #888;
                margin-top: 10px;
            }}
            .stats-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .stat-card {{
                background: linear-gradient(145deg, #1e2a4a, #16213e);
                border-radius: 15px;
                padding: 25px;
                text-align: center;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                border: 1px solid #0f3460;
            }}
            .stat-card h3 {{
                color: #888;
                font-size: 0.9em;
                margin-bottom: 10px;
            }}
            .stat-card .value {{
                font-size: 2.5em;
                font-weight: bold;
            }}
            .stat-card.danger .value {{
                color: #ff4757;
            }}
            .stat-card.warning .value {{
                color: #ffa502;
            }}
            .stat-card.success .value {{
                color: #2ed573;
            }}
            .stat-card.info .value {{
                color: #00d4ff;
            }}
            .charts-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
                gap: 20px;
                margin-bottom: 30px;
            }}
            .chart-container {{
                background: linear-gradient(145deg, #1e2a4a, #16213e);
                border-radius: 15px;
                padding: 25px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                border: 1px solid #0f3460;
            }}
            .chart-container h3 {{
                color: #00d4ff;
                margin-bottom: 20px;
                font-size: 1.2em;
            }}
            .table-container {{
                background: linear-gradient(145deg, #1e2a4a, #16213e);
                border-radius: 15px;
                padding: 25px;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                border: 1px solid #0f3460;
                overflow-x: auto;
            }}
            .table-container h3 {{
                color: #ff4757;
                margin-bottom: 20px;
                font-size: 1.3em;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
            }}
            th, td {{
                padding: 12px 15px;
                text-align: left;
                border-bottom: 1px solid #0f3460;
            }}
            th {{
                background: #0f3460;
                color: #00d4ff;
                font-weight: 600;
            }}
            tr:hover {{
                background: rgba(0, 212, 255, 0.05);
            }}
            .badge {{
                padding: 5px 12px;
                border-radius: 20px;
                font-size: 0.85em;
                font-weight: 600;
            }}
            .badge-danger {{
                background: rgba(255, 71, 87, 0.2);
                color: #ff4757;
                border: 1px solid #ff4757;
            }}
            .risk-score {{
                color: #ff4757;
                font-weight: bold;
            }}
            .url-cell {{
                max-width: 200px;
                overflow: hidden;
                text-overflow: ellipsis;
                white-space: nowrap;
            }}
            .reason-cell {{
                max-width: 300px;
                font-size: 0.85em;
                color: #aaa;
            }}
            .refresh-btn {{
                position: fixed;
                bottom: 30px;
                right: 30px;
                background: #00d4ff;
                color: #1a1a2e;
                border: none;
                padding: 15px 30px;
                border-radius: 30px;
                font-size: 1em;
                font-weight: bold;
                cursor: pointer;
                box-shadow: 0 5px 20px rgba(0, 212, 255, 0.4);
                transition: all 0.3s;
            }}
            .refresh-btn:hover {{
                transform: scale(1.05);
                box-shadow: 0 8px 30px rgba(0, 212, 255, 0.6);
            }}
            .no-data {{
                text-align: center;
                color: #666;
                padding: 40px;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ 안다(An-Da) 대시보드</h1>
            <p>고령층 보호를 위한 AI 기반 피싱 탐지 모니터링 시스템</p>
        </div>

        <div class="stats-grid">
            <div class="stat-card info">
                <h3>전체 분석 건수</h3>
                <div class="value">{stats['total_analyses']:,}</div>
            </div>
            <div class="stat-card danger">
                <h3>피싱 탐지 건수</h3>
                <div class="value">{stats['phishing_detected']:,}</div>
            </div>
            <div class="stat-card warning">
                <h3>탐지율</h3>
                <div class="value">{stats['detection_rate']*100:.1f}%</div>
            </div>
            <div class="stat-card success">
                <h3>평균 위험 점수</h3>
                <div class="value">{stats['average_risk_score']*100:.1f}%</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-container">
                <h3>📊 사칭 브랜드 현황</h3>
                <canvas id="brandChart"></canvas>
            </div>
            <div class="chart-container">
                <h3>📈 일별 탐지 추이 (최근 30일)</h3>
                <canvas id="dailyChart"></canvas>
            </div>
        </div>

        <div class="table-container">
            <h3>🚨 최근 피싱 탐지 케이스 (경찰 보고용)</h3>
            {"<p class='no-data'>탐지된 피싱 사례가 없습니다.</p>" if not phishing_cases else f'''
            <table>
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>사칭 브랜드</th>
                        <th>도메인</th>
                        <th>도메인 생성일</th>
                        <th>위험도</th>
                        <th>AI 판별 근거</th>
                        <th>탐지일</th>
                    </tr>
                </thead>
                <tbody>
                    {cases_html}
                </tbody>
            </table>
            '''}
        </div>

        <button class="refresh-btn" onclick="location.reload()">🔄 새로고침</button>

        <script>
            // 브랜드별 차트
            const brandCtx = document.getElementById('brandChart').getContext('2d');
            new Chart(brandCtx, {{
                type: 'doughnut',
                data: {{
                    labels: {brand_labels},
                    datasets: [{{
                        data: {brand_counts},
                        backgroundColor: [
                            '#ff4757', '#ffa502', '#2ed573', '#00d4ff',
                            '#a55eea', '#ff6b81', '#70a1ff', '#7bed9f'
                        ],
                        borderWidth: 0
                    }}]
                }},
                options: {{
                    responsive: true,
                    plugins: {{
                        legend: {{
                            position: 'bottom',
                            labels: {{ color: '#e8e8e8' }}
                        }}
                    }}
                }}
            }});

            // 일별 추이 차트
            const dailyCtx = document.getElementById('dailyChart').getContext('2d');
            new Chart(dailyCtx, {{
                type: 'line',
                data: {{
                    labels: {daily_dates},
                    datasets: [
                        {{
                            label: '전체 분석',
                            data: {daily_totals},
                            borderColor: '#00d4ff',
                            backgroundColor: 'rgba(0, 212, 255, 0.1)',
                            fill: true,
                            tension: 0.4
                        }},
                        {{
                            label: '피싱 탐지',
                            data: {daily_phishing},
                            borderColor: '#ff4757',
                            backgroundColor: 'rgba(255, 71, 87, 0.1)',
                            fill: true,
                            tension: 0.4
                        }}
                    ]
                }},
                options: {{
                    responsive: true,
                    scales: {{
                        x: {{
                            grid: {{ color: 'rgba(255,255,255,0.1)' }},
                            ticks: {{ color: '#888' }}
                        }},
                        y: {{
                            grid: {{ color: 'rgba(255,255,255,0.1)' }},
                            ticks: {{ color: '#888' }}
                        }}
                    }},
                    plugins: {{
                        legend: {{
                            labels: {{ color: '#e8e8e8' }}
                        }}
                    }}
                }}
            }});
        </script>
    </body>
    </html>
    """

    return HTMLResponse(content=html_content)
