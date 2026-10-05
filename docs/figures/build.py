"""Generate the architecture and protocol figures (English and French).

All connectors are orthogonal polylines: no curves. Run:
    python docs/figures/build.py
"""

from __future__ import annotations

from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).resolve().parent
FONT = "Inter, 'Segoe UI', Helvetica, Arial, sans-serif"
INK, MUTED, LINE = "#0f172a", "#475569", "#334155"
PALETTE = {
    "trust": ("#eef2ff", "#4f46e5"),
    "control": ("#eff6ff", "#2563eb"),
    "data": ("#ecfdf5", "#059669"),
    "audit": ("#fff7ed", "#c2410c"),
    "identity": ("#f5f3ff", "#7c3aed"),
    "storage": ("#f1f5f9", "#64748b"),
    "frame": ("#ffffff", "#94a3b8"),
}

TEXT = {
    "en": {
        "arch_title": "Trustworthy Data Space — architecture",
        "arch_sub": "Three planes: trust (shared services), control (contracts and policies), data (content, peer to peer)",
        "trust_plane": "TRUST PLANE — shared services",
        "authority": "Authority (trust anchor)", "authority_l": "verifiable credentials · revocation",
        "catalog": "Federated catalog", "catalog_l": "signed DCAT 3 offers · ODRL 2.2",
        "log": "Transparency log", "log_l": "Merkle tree · RFC 9162 proofs",
        "conn_a": "Participant A — provider", "conn_b": "Participant B — consumer",
        "connector": "Connector",
        "wallet": "Identity wallet", "wallet_l": "DID key · credentials · presentations",
        "control": "Control plane", "control_l": "offers · negotiation · PDP / PEP",
        "data": "Data plane", "data_l": "single-use data address · attestation",
        "audit": "Audit trail", "audit_l": "hash chain · anchored receipts",
        "postgres": "PostgreSQL", "postgres_l": "contracts · audit",
        "minio": "MinIO (S3)", "minio_l": "dataset content",
        "credentials": "credentials", "offers": "signed offers", "discovery": "discovery",
        "receipts": "signed receipts", "no_data": "no data path",
        "protocol": "Dataspace protocol — negotiation · signed agreement · transfer · data pull",
        "note": "Data never transits through the trust plane: it flows only from provider to consumer, under a signed agreement.",
        "seq_title": "Protocol — from onboarding to verifiable evidence",
        "seq_sub": "Messages between independent services; every arrow is an authenticated HTTP exchange",
        "lifelines": ["Authority", "Consumer B", "Provider A", "Catalog", "Transparency log"],
        "phases": ["1  Onboarding", "2  Publication and discovery", "3  Contract negotiation", "4  Transfer", "5  Accountability"],
        "steps": [
            ("msg", 1, 0, "presentation proving control of its DID"),
            ("msg", 0, 1, "verifiable credentials (attested facts only)"),
            ("msg", 2, 3, "offer signed by A (DCAT + ODRL)"),
            ("msg", 1, 3, "search"),
            ("msg", 3, 1, "offer — B verifies A's signature itself"),
            ("msg", 1, 2, "contract request + presentation (audience A, nonce)"),
            ("self", 2, None, "verify credentials · revocation · evaluate policy"),
            ("msg", 2, 1, "agreement signed by A"),
            ("msg", 1, 2, "countersignature → agreement FINALIZED"),
            ("msg", 1, 2, "transfer request + fresh presentation"),
            ("self", 2, None, "re-evaluate the current policy (continuous control)"),
            ("msg", 2, 1, "single-use data address (5 min)"),
            ("msg", 1, 2, "pull data with bearer token"),
            ("msg", 2, 1, "data + signed attestation (SHA-256)"),
            ("self", 1, None, "verify checksum and provider signature"),
            ("msg", 2, 4, "signed receipt of each audit event"),
            ("msg", 1, 4, "signed receipt of each audit event"),
            ("msg", 4, 1, "inclusion + consistency proofs, signed tree head"),
        ],
        "phase_rows": [0, 2, 5, 9, 15],
    },
    "fr": {
        "arch_title": "Espace de données de confiance — architecture",
        "arch_sub": "Trois plans : confiance (services partagés), contrôle (contrats et politiques), données (contenu, pair à pair)",
        "trust_plane": "PLAN DE CONFIANCE — services partagés",
        "authority": "Autorité (ancre de confiance)", "authority_l": "attestations vérifiables · révocation",
        "catalog": "Catalogue fédéré", "catalog_l": "offres DCAT 3 signées · ODRL 2.2",
        "log": "Journal de transparence", "log_l": "arbre de Merkle · preuves RFC 9162",
        "conn_a": "Participant A — fournisseur", "conn_b": "Participant B — consommateur",
        "connector": "Connecteur",
        "wallet": "Portefeuille d'identité", "wallet_l": "clé DID · attestations · présentations",
        "control": "Plan de contrôle", "control_l": "offres · négociation · PDP / PEP",
        "data": "Plan de données", "data_l": "adresse à usage unique · attestation",
        "audit": "Piste d'audit", "audit_l": "chaîne de hachage · reçus ancrés",
        "postgres": "PostgreSQL", "postgres_l": "contrats · audit",
        "minio": "MinIO (S3)", "minio_l": "contenu des jeux",
        "credentials": "attestations", "offers": "offres signées", "discovery": "découverte",
        "receipts": "reçus signés", "no_data": "aucun flux de données",
        "protocol": "Protocole d'espace de données — négociation · contrat signé · transfert · récupération",
        "note": "Les données ne transitent jamais par le plan de confiance : elles vont du fournisseur au consommateur, sous contrat signé.",
        "seq_title": "Protocole — de l'enrôlement à la preuve vérifiable",
        "seq_sub": "Messages entre services indépendants ; chaque flèche est un échange HTTP authentifié",
        "lifelines": ["Autorité", "Consommateur B", "Fournisseur A", "Catalogue", "Journal de transparence"],
        "phases": ["1  Enrôlement", "2  Publication et découverte", "3  Négociation du contrat", "4  Transfert", "5  Redevabilité"],
        "steps": [
            ("msg", 1, 0, "présentation prouvant le contrôle de son DID"),
            ("msg", 0, 1, "attestations vérifiables (faits vérifiés uniquement)"),
            ("msg", 2, 3, "offre signée par A (DCAT + ODRL)"),
            ("msg", 1, 3, "recherche"),
            ("msg", 3, 1, "offre — B vérifie lui-même la signature de A"),
            ("msg", 1, 2, "demande de contrat + présentation (audience A, nonce)"),
            ("self", 2, None, "vérifie attestations · révocation · évalue la politique"),
            ("msg", 2, 1, "contrat signé par A"),
            ("msg", 1, 2, "contre-signature → contrat FINALISÉ"),
            ("msg", 1, 2, "demande de transfert + présentation fraîche"),
            ("self", 2, None, "réévalue la politique courante (contrôle continu)"),
            ("msg", 2, 1, "adresse de données à usage unique (5 min)"),
            ("msg", 1, 2, "récupère les données avec le jeton"),
            ("msg", 2, 1, "données + attestation signée (SHA-256)"),
            ("self", 1, None, "vérifie l'empreinte et la signature du fournisseur"),
            ("msg", 2, 4, "reçu signé de chaque événement d'audit"),
            ("msg", 1, 4, "reçu signé de chaque événement d'audit"),
            ("msg", 4, 1, "preuves d'inclusion et de cohérence, tête d'arbre signée"),
        ],
        "phase_rows": [0, 2, 5, 9, 15],
    },
}


class Svg:
    def __init__(self, width: int, height: int):
        self.width, self.height = width, height
        self.parts: list[str] = []

    def add(self, element: str) -> None:
        self.parts.append(element)

    def text(self, x, y, content, size=12, weight=400, fill=INK, anchor="start", italic=False):
        style = ' font-style="italic"' if italic else ""
        self.add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{fill}" '
                 f'text-anchor="{anchor}"{style}>{escape(content)}</text>')

    def rect(self, x, y, w, h, fill, stroke, dash=False, width=1.5, rx=6):
        dashing = ' stroke-dasharray="6 4"' if dash else ""
        self.add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{rx}" fill="{fill}" '
                 f'stroke="{stroke}" stroke-width="{width}"{dashing}/>')

    def line(self, points, color=LINE, start=False, end=True, dash=False, width=1.6):
        path = " ".join(f"{x},{y}" for x, y in points)
        markers = (' marker-start="url(#arrow-start)"' if start else "") + (' marker-end="url(#arrow)"' if end else "")
        dashing = ' stroke-dasharray="5 4"' if dash else ""
        self.add(f'<polyline points="{path}" fill="none" stroke="{color}" stroke-width="{width}" '
                 f'stroke-linejoin="miter"{dashing}{markers}/>')

    def render(self) -> str:
        defs = (
            '<defs>'
            f'<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto">'
            f'<path d="M0,0 L10,5 L0,10 z" fill="{LINE}"/></marker>'
            f'<marker id="arrow-start" viewBox="0 0 10 10" refX="1" refY="5" markerWidth="8" markerHeight="8" orient="auto">'
            f'<path d="M10,0 L0,5 L10,10 z" fill="{LINE}"/></marker>'
            '</defs>'
        )
        return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{self.width}" height="{self.height}" '
                f'viewBox="0 0 {self.width} {self.height}" font-family="{FONT}">{defs}'
                f'<rect width="100%" height="100%" fill="#ffffff"/>' + "".join(self.parts) + "</svg>")


def component(svg: Svg, x, y, w, h, kind, title, lines):
    fill, stroke = PALETTE[kind]
    svg.rect(x, y, w, h, fill, stroke)
    svg.rect(x, y, 5, h, stroke, stroke, rx=2, width=0)
    svg.text(x + 16, y + 22, title, size=13, weight=600)
    for i, line in enumerate(lines if isinstance(lines, list) else [lines]):
        svg.text(x + 16, y + 40 + i * 16, line, size=11.5, fill=MUTED)


def label(svg: Svg, x, y, content, anchor="middle"):
    svg.text(x, y, content, size=11, weight=500, fill=MUTED, anchor=anchor)


def architecture(t: dict) -> str:
    svg = Svg(1180, 740)
    svg.text(40, 42, t["arch_title"], size=20, weight=700)
    svg.text(40, 64, t["arch_sub"], size=12.5, fill=MUTED)
    rows = {"wallet": 160, "control": 244, "data": 328, "audit": 412}
    h = 70

    def connector(x, title, did):
        svg.rect(x, 96, 340, 520, *PALETTE["frame"], width=1.5)
        svg.text(x + 20, 124, title, size=15, weight=700)
        svg.text(x + 20, 143, f'{t["connector"]} · {did}', size=11.5, fill=MUTED)
        component(svg, x + 20, rows["wallet"], 300, h, "identity", t["wallet"], [t["wallet_l"]])
        component(svg, x + 20, rows["control"], 300, h, "control", t["control"], [t["control_l"]])
        component(svg, x + 20, rows["data"], 300, h, "data", t["data"], [t["data_l"]])
        component(svg, x + 20, rows["audit"], 300, h, "audit", t["audit"], [t["audit_l"]])
        for cx in (x + 92, x + 247):
            svg.line([(cx, 486), (cx, 524)], color=PALETTE["storage"][1], start=True)
        component(svg, x + 20, 526, 145, 70, "storage", t["postgres"], [t["postgres_l"]])
        component(svg, x + 175, 526, 145, 70, "storage", t["minio"], [t["minio_l"]])

    connector(40, t["conn_a"], "did:web:connector-a")
    connector(800, t["conn_b"], "did:web:connector-b")

    # trust plane: each shared service faces the connector component it serves
    svg.rect(460, 96, 260, 520, "#fafaff", PALETTE["trust"][1], dash=True)
    svg.text(590, 124, t["trust_plane"], size=11, weight=700, fill=PALETTE["trust"][1], anchor="middle")
    component(svg, 480, rows["wallet"], 220, h, "trust", t["authority"], [t["authority_l"]])
    component(svg, 480, rows["control"], 220, h, "trust", t["catalog"], [t["catalog_l"]])
    component(svg, 480, rows["audit"], 220, h, "trust", t["log"], [t["log_l"]])
    svg.text(590, rows["data"] + 40, t["no_data"], size=11.5, fill=PALETTE["trust"][1], anchor="middle", italic=True)

    def link(row, text, towards_connector):
        y = rows[row] + h / 2
        if towards_connector:
            svg.line([(480, y), (360, y)]); svg.line([(700, y), (820, y)])
        else:
            svg.line([(360, y), (480, y)]); svg.line([(820, y), (700, y)])
        for x, content in ((420, text[0]), (760, text[1])):
            label(svg, x, y - 8, content)

    link("wallet", (t["credentials"], t["credentials"]), True)
    link("control", (t["offers"], t["discovery"]), False)
    link("audit", (t["receipts"], t["receipts"]), False)

    # peer-to-peer protocol, routed below the trust plane
    svg.line([(210, 616), (210, 656), (970, 656), (970, 616)], width=2.2, start=True)
    width = 7 * len(t["protocol"])
    svg.rect(590 - width / 2, 643, width, 26, "#ffffff", "#ffffff", rx=0, width=0)
    svg.text(590, 661, t["protocol"], size=12, weight=600, anchor="middle")

    svg.rect(40, 684, 1100, 40, "#f8fafc", "#e2e8f0", rx=6, width=1)
    svg.text(590, 709, t["note"], size=12, fill=MUTED, anchor="middle", italic=True)
    return svg.render()


def sequence(t: dict) -> str:
    xs = [120, 340, 580, 820, 1040]
    top, row = 130, 34
    steps = t["steps"]
    height = top + 40 + len(steps) * row + len(t["phases"]) * 26 + 40
    svg = Svg(1160, height)
    svg.text(40, 42, t["seq_title"], size=20, weight=700)
    svg.text(40, 64, t["seq_sub"], size=12.5, fill=MUTED)

    kinds = ["trust", "control", "control", "trust", "audit"]
    for x, name, kind in zip(xs, t["lifelines"], kinds):
        fill, stroke = PALETTE[kind]
        svg.rect(x - 85, 84, 170, 34, fill, stroke)
        svg.text(x, 106, name, size=13, weight=600, anchor="middle")
        svg.add(f'<line x1="{x}" y1="118" x2="{x}" y2="{height - 30}" stroke="#cbd5e1" stroke-width="1.5" stroke-dasharray="4 4"/>')

    y = top + 10
    phase_starts = dict(zip(t["phase_rows"], t["phases"]))
    for i, (kind, src, dst, content) in enumerate(steps):
        if i in phase_starts:
            y += 8
            svg.rect(30, y - 2, 1100, 22, "#f1f5f9", "#f1f5f9", rx=3, width=0)
            svg.text(40, y + 14, phase_starts[i], size=11.5, weight=700, fill=PALETTE["trust"][1])
            y += 36
        if kind == "msg":
            x1, x2 = xs[src], xs[dst]
            svg.line([(x1, y + 8), (x2, y + 8)])
            width = 6.3 * len(content)
            svg.rect((x1 + x2) / 2 - width / 2, y - 11, width, 16, "#ffffff", "#ffffff", rx=0, width=0)
            svg.text((x1 + x2) / 2, y + 2, content, size=11.5, anchor="middle")
        else:
            x = xs[src]
            svg.rect(x - 6, y - 6, 12, 24, PALETTE["control"][0], PALETTE["control"][1], rx=2, width=1.2)
            svg.rect(x + 10, y - 3, 6.2 * len(content), 18, "#ffffff", "#ffffff", rx=0, width=0)
            svg.text(x + 14, y + 11, content, size=11.5, fill=MUTED, italic=True)
        y += row
    return svg.render()


def main() -> None:
    for lang, t in TEXT.items():
        suffix = "" if lang == "en" else f".{lang}"
        (OUT / f"architecture{suffix}.svg").write_text(architecture(t))
        (OUT / f"protocol{suffix}.svg").write_text(sequence(t))
    print("figures written to", OUT)


if __name__ == "__main__":
    main()
