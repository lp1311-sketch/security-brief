import { createServerFn } from "@tanstack/react-start";
import { queryOptions } from "@tanstack/react-query";
import { loadChangeRadar, type ChangeRadarSnapshot } from "./change-radar";

let cache: { at: number; data: ChangeRadarSnapshot } | null = null;
const SUCCESS_TTL = 20 * 60 * 1000;
const ERROR_TTL = 30 * 1000;

export const getChangeRadar = createServerFn({ method: "GET" }).handler(async (): Promise<ChangeRadarSnapshot> => {
  const ttl = cache?.data.ok ? SUCCESS_TTL : ERROR_TTL;
  if (cache && Date.now() - cache.at < ttl) return cache.data;
  const data = await loadChangeRadar();
  cache = { at: Date.now(), data };
  return data;
});

export const changeRadarQuery = queryOptions({
  queryKey: ["microsoft-365-change-radar"],
  queryFn: () => getChangeRadar(),
  staleTime: 10 * 60 * 1000,
});
