import { createServerFn } from "@tanstack/react-start";
import { queryOptions } from "@tanstack/react-query";
import { runPipeline } from "./pipeline";
import type { NewsSnapshot } from "./types";

let cache: { at: number; data: NewsSnapshot } | null = null;
const TTL = 20 * 60 * 1000;

export const getNews = createServerFn({ method: "GET" }).handler(async (): Promise<NewsSnapshot> => {
  if (cache && Date.now() - cache.at < TTL) return cache.data;
  const data = await runPipeline();
  if (data.clusters.length) cache = { at: Date.now(), data };
  return data;
});

export const newsQuery = queryOptions({
  queryKey: ["news"],
  queryFn: () => getNews(),
  staleTime: 10 * 60 * 1000,
});
