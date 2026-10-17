"""Best Wi-Fi channel for the user's router, from the neighbouring networks the WiFiSense agent saw.

Two routers on the same channel take turns to talk, and on 2.4 GHz channels that are close together also step on each
other (only 1, 6 and 11 do not overlap). The recommendation counts, for each channel the router could use, how many
neighbouring access points interfere with it, weighting the partially overlapping ones less, and suggests moving only
when another channel is clearly calmer: changing the channel disconnects every device for a few seconds.
"""
from app.schemas_channel import ChannelCount, ChannelOption, ChannelRequest, ChannelResponse

MODEL_VERSION = "channel-1.0"

# Channels worth recommending in Colombia (and most of the Americas): the three that do not overlap on 2.4 GHz and the
# non-radar ones on 5 GHz (every device supports them). 6 GHz is not compared: its channel numbers repeat those of the
# other bands, so the agent's counts cannot tell them apart, and it is almost always free anyway.
CANDIDATES = {
    "2.4": [1, 6, 11],
    "5": [36, 40, 44, 48, 149, 153, 157, 161, 165],
}

# Routers on 5 GHz usually bond channels in blocks of 80 MHz (36-48, 52-64...): a neighbour in the same block shares
# part of the air even on a different primary channel.
BLOCKS_5GHZ = (36, 52, 100, 116, 132, 149)

# Moving is worth it only if the new channel has at least one interfering network less (one full neighbour).
MIN_GAIN = 1.0


def band_of(channel: int) -> str | None:
    if 1 <= channel <= 14:
        return "2.4"
    if 32 <= channel <= 177:
        return "5"
    return None


def block_of(channel: int) -> int:
    for start in BLOCKS_5GHZ:
        if start <= channel < start + 16:
            return start
    return channel


def overlap(band: str, a: int, b: int) -> float:
    """How much a neighbour on channel b interferes with channel a: 1 on the same channel, less when partially."""
    if a == b:
        return 1.0
    if band == "2.4":
        return max(0.0, 1 - abs(a - b) / 5)  # 2.4 GHz channels are 5 MHz apart and about 20 MHz wide
    if band == "5" and block_of(a) == block_of(b):
        return 0.5
    return 0.0


def load(band: str, channel: int, neighbours: list[ChannelCount]) -> float:
    return round(sum(n.networks * overlap(band, channel, n.channel) for n in neighbours), 1)


def crowd(band: str, channel: int, neighbours: list[ChannelCount]) -> str:
    """Whole numbers for people: "4 redes vecinas y 1 más en un canal encimado", or "" when there is none."""
    same = sum(n.networks for n in neighbours if n.channel == channel)
    near = sum(n.networks for n in neighbours if n.channel != channel and overlap(band, channel, n.channel) > 0)
    parts = []
    if same:
        parts.append(f"{same} red vecina" if same == 1 else f"{same} redes vecinas")
    if near:
        more = "más " if same else ""
        parts.append(f"{near} {more}en un canal encimado" if near == 1 else f"{near} {more}en canales encimados")
    return " y ".join(parts)


def recommend(request: ChannelRequest) -> ChannelResponse:
    band = request.band or (band_of(request.channel) if request.channel else None)
    current = request.channel
    if band == "6":
        return ChannelResponse(
            band=band, current_channel=current, current_load=None, recommended_channel=current, recommended_load=None,
            should_change=False, options=[], action=None, model_version=MODEL_VERSION,
            summary="Tu Wi-Fi usa 6 GHz, donde casi no hay redes vecinas: no hace falta cambiar el canal.")
    if not request.channel_counts or band not in CANDIDATES:
        return ChannelResponse(
            band=band, current_channel=current, current_load=None, recommended_channel=None, recommended_load=None,
            should_change=False, options=[], action=None, model_version=MODEL_VERSION,
            summary="No pudimos ver las redes vecinas, así que todavía no hay con qué comparar el canal.")

    neighbours = [n for n in request.channel_counts if band_of(n.channel) == band]
    on_channel = {n.channel: n.networks for n in neighbours}
    candidates = CANDIDATES[band]
    options = [ChannelOption(channel=c, networks=on_channel.get(c, 0), load=load(band, c, neighbours))
               for c in candidates]
    # Ties go to the current channel (no reason to move) and then to the lowest one.
    best = min(options, key=lambda o: (o.load, o.channel != current, o.channel))
    current_load = load(band, current, neighbours) if current else None

    if current is None:
        summary = (f"No sabemos en qué canal está tu router, pero en {band} GHz el que tiene menos interferencia es "
                   f"el {best.channel}.")
        should_change = False
    else:
        gain = current_load - best.load
        off_grid = band == "2.4" and current not in candidates
        should_change = best.channel != current and (gain >= MIN_GAIN or (off_grid and gain > 0))
        if should_change:
            now_crowd = crowd(band, current, neighbours)
            best_crowd = crowd(band, best.channel, neighbours)
            summary = (f"Tu router usa el canal {current}, donde hay {now_crowd}. "
                       + (f"En el canal {best.channel} hay {best_crowd}." if best_crowd
                          else f"En el canal {best.channel} no hay ninguna."))
            if off_grid:
                summary += " En 2,4 GHz solo los canales 1, 6 y 11 no se pisan entre sí."
        elif current_load == 0:
            summary = f"Tu canal ({current}) está libre: ninguna red vecina interfiere con tu Wi-Fi."
        else:
            summary = (f"Tu router ya está en un buen canal ({current}): ningún otro tiene claramente menos "
                       f"interferencia, así que no vale la pena cambiarlo.")

    action = (f"Entra a la configuración del router (suele ser 192.168.0.1 o 192.168.1.1), busca Wi-Fi {band} GHz → "
              f"Canal, cambia «Automático» por {best.channel} y guarda. Tus equipos se reconectan solos en unos "
              f"segundos.") if should_change else None
    return ChannelResponse(
        band=band, current_channel=current, current_load=current_load, recommended_channel=best.channel,
        recommended_load=best.load, should_change=should_change, summary=summary, action=action, options=options,
        model_version=MODEL_VERSION)
