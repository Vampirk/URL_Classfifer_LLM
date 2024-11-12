class URLAnalyzer {
    formatAnalysisResult(result) {
        try {
            let output = "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
            output += "                    URL 보안 분석 보고서                    \n";
            output += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

            const { url, technical_analysis, llm_analysis, tokens_used } = result;

            // 분석 대상
            output += "▶ 분석 대상\n";
            output += "────────────────────────────────────────────────────\n";
            output += `URL: ${url || 'N/A'}\n\n`;

            if (llm_analysis) {
                // 분류 결과
                output += "▶ 분류 결과\n";
                output += "────────────────────────────────────────────────────\n";
                output += `【${llm_analysis.classification}】\n\n`;

                // 보안 평가
                output += "▶ 보안 평가\n";
                output += "────────────────────────────────────────────────────\n";
                llm_analysis.security_assessment.forEach(assessment => {
                    output += `◆ ${assessment}\n`;
                });
                output += "\n";

                // 주요 발견사항
                if (llm_analysis.key_findings?.length > 0) {
                    output += "▶ 주요 발견사항\n";
                    output += "────────────────────────────────────────────────────\n";
                    llm_analysis.key_findings.forEach((finding, i) => {
                        output += `${i + 1}. ${finding}\n`;
                    });
                    output += "\n";
                }

                // 위험도 평가
                output += "▶ 위험도 평가\n";
                output += "────────────────────────────────────────────────────\n";
                output += `【${llm_analysis.risk_assessment}】\n\n`;

                // 권장사항
                if (llm_analysis.technical_recommendations?.length > 0) {
                    output += "▶ 보안 권장사항\n";
                    output += "────────────────────────────────────────────────────\n";
                    llm_analysis.technical_recommendations.forEach((rec, i) => {
                        output += `${i + 1}. ${rec}\n`;
                    });
                    output += "\n";
                }
            }

            // 메타데이터
            output += "▶ 분석 메타데이터\n";
            output += "────────────────────────────────────────────────────\n";
            output += `◆ 처리된 토큰 수: ${tokens_used || 'N/A'}\n`;
            output += `◆ 분석 시간: ${new Date().toLocaleString('ko-KR')}\n\n`;

            return this.wrapInPre(output);
        } catch (error) {
            console.error('Error formatting analysis result:', error);
            return this.wrapInPre('분석 결과 포맷팅 중 오류가 발생했습니다.');
        }
    }

    formatHealthResult(data) {
        try {
            let output = "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n";
            output += "                    시스템 상태 보고서                    \n";
            output += "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n\n";

            // 시스템 상태
            output += "▶ 시스템 상태\n";
            output += "────────────────────────────────────────────────────\n";
            const statusEmoji = data.status === 'healthy' ? '✅' : '⚠️';
            output += `${statusEmoji} 상태: ${data.status === 'healthy' ? '정상' : '비정상'}\n`;

            // GPU 상태
            if (data.gpu_available) {
                output += "\n▶ GPU 상태\n";
                output += "────────────────────────────────────────────────────\n";
                output += `◆ GPU 사용 가능: ${data.gpu_available ? '✅' : '❌'}\n`;
                output += `◆ 할당된 메모리: ${data.gpu_memory_allocated}\n`;
            }

            output += "\n◆ 마지막 확인: " + new Date().toLocaleString('ko-KR') + "\n";

            return this.wrapInPre(output);
        } catch (error) {
            console.error('Error formatting health result:', error);
            return this.wrapInPre('시스템 상태 정보 포맷팅 중 오류가 발생했습니다.');
        }
    }

    wrapInPre(text) {
        return `<pre>${text}</pre>`;
    }
}
