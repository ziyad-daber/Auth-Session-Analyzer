"""
backend/report_generator/pdf_generator.py
─────────────────────────────────────────────
Génération de rapports PDF professionnels via ReportLab.
"""

from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.units import inch
import os

class PDFReportGenerator:
    def __init__(self, output_path: str):
        self.output_path = output_path
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()

    def _setup_custom_styles(self):
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Title'],
            fontSize=24,
            textColor=colors.HexColor("#FF4B2B"),
            spaceAfter=30
        ))
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor("#2B2D42"),
            spaceBefore=20,
            spaceAfter=10
        ))

    def generate(self, data: dict):
        doc = SimpleDocTemplate(self.output_path, pagesize=A4)
        elements = []

        # 1. Header
        elements.append(Paragraph("RAPPORT D'AUDIT SÉCURITÉ AUTH & SESSION", self.styles['ReportTitle']))
        elements.append(Paragraph(f"Application : {data.get('apk_name', 'Inconnue')}", self.styles['Normal']))
        elements.append(Paragraph(f"Package : {data.get('package_name', 'N/A')}", self.styles['Normal']))
        elements.append(Spacer(1, 0.2*inch))

        # 2. Résumé du Risque & Score Breakdown
        score_data = data.get('risk_score_details', {})
        elements.append(Paragraph("Résumé du Risque & Score Breakdown", self.styles['SectionHeader']))
        
        # Table de score
        score_table = [
            ["Niveau de Risque", score_data.get('level', 'N/A')],
            ["Score Numérique", f"{score_data.get('score', 0)} / {score_data.get('max_score', 150)}"],
        ]
        
        # Ajout du breakdown
        breakdown = data.get('score_breakdown', [])
        for item in breakdown:
            score_table.append([f"+{item['points']} {item['type']}", item['owasp']])

        t = Table(score_table, colWidths=[2.5*inch, 3.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, 1), colors.lightgrey),
            ('TEXTCOLOR', (1, 0), (1, 0), colors.red if score_data.get('level') == 'CRITIQUE' else colors.black),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('FONTSIZE', (0, 2), (-1, -1), 8),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        elements.append(t)
        elements.append(Spacer(1, 0.3*inch))

        # 3. Détails des Vulnérabilités & Impact
        elements.append(Paragraph("Détails des Failles & Impact Métier", self.styles['SectionHeader']))
        
        import html
        for f in data.get('findings', []):
            title = html.escape(f"[{f.get('severity', 'INFO')}] {f.get('type')}")
            elements.append(Paragraph(f"<b>{title}</b>", self.styles['Normal']))
            
            # IMPACT BLOCK
            impact = f.get('impact', "Risque de compromission des données utilisateur.")
            elements.append(Paragraph(f"<font color='red'>💥 IMPACT :</font> {html.escape(impact)}", self.styles['Normal']))
            
            desc = html.escape(f.get('description', 'N/A'))
            elements.append(Paragraph(f"Description : {desc}", self.styles['Normal']))
            
            if f.get('owasp'):
                elements.append(Paragraph(f"Mapping OWASP : {html.escape(f.get('owasp'))}", self.styles['Italic']))
            
            # CODE SNIPPET BLOCK
            if f.get('snippet'):
                snippet = html.escape(f.get('snippet'))
                elements.append(Paragraph("<b>Source Evidence :</b>", self.styles['Normal']))
                elements.append(Paragraph(f"<font face='Courier' size='7'>{snippet.replace('\\n', '<br/>')}</font>", self.styles['Normal']))
            
            elements.append(Spacer(1, 0.15*inch))

        # 4. Résultats des Attaques (Exploitation)
        elements.append(Paragraph("Tests d'Exploitation (Active Validation)", self.styles['SectionHeader']))
        
        attack_results = data.get('attack_results', [])
        if not attack_results:
            elements.append(Paragraph("Aucun test d'exploitation n'a été effectué.", self.styles['Italic']))
        else:
            for atk in attack_results:
                title = html.escape(atk.get('type', 'Attaque'))
                elements.append(Paragraph(f"<b>Test : {title}</b>", self.styles['Normal']))
                
                status = atk.get('status', 'N/A')
                color = colors.red if "VULNÉRABLE" in status or "SUCCÈS" in status else colors.green
                elements.append(Paragraph(f"Résultat : <font color='{color}'>{html.escape(status)}</font>", self.styles['Normal']))
                
                if atk.get('owasp'):
                    elements.append(Paragraph(f"OWASP : {html.escape(atk.get('owasp'))}", self.styles['Italic']))
                
                if atk.get('details'):
                    elements.append(Paragraph(f"Détails : {html.escape(atk.get('details'))}", self.styles['Normal']))
                
                if atk.get('evidence'):
                    elements.append(Paragraph(f"Preuve : {html.escape(atk.get('evidence'))}", self.styles['Normal']))
                    
                elements.append(Spacer(1, 0.1*inch))

        # 5. Recommandations IA (Claude/GPT)
        elements.append(Paragraph("Recommandations Stratégiques & Remédiations", self.styles['SectionHeader']))
        recos = data.get('ai_recommendations', "Aucune recommandation générée.")
        recos_html = html.escape(recos).replace("\n", "<br/>")
        elements.append(Paragraph(recos_html, self.styles['Normal']))

        doc.build(elements)
        return self.output_path
