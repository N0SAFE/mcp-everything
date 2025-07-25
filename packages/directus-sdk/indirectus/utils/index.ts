import { DirectusClient, QueryFields, UnpackList } from "@directus/sdk";
import { Types, Schema, CollectionsType } from "../client";
import { ApplyQueryFields } from "../types/ApplyQueryFields";
import * as DirectusFileNamespace from "./DirectusFile";

export type ApplyFields<
  Collection extends UnpackList<CollectionsType[keyof CollectionsType]>,
  Fields extends QueryFields<CollectionsType, Collection> | unknown = unknown,
> = ApplyQueryFields<CollectionsType, Collection, Fields>;

export type ItemNoRelations<Collection extends object> = {
  [Key in keyof Collection]: Collection[Key] extends { id: DirectusIdType }
    ? DirectusItemExcludeRelations<Collection[Key]>
    : Collection[Key] extends { id: DirectusIdType }[]
      ? DirectusItemExcludeRelations<Collection[Key][number]>[]
      : Collection[Key];
};

export type DirectusIdType = string | number;

// Define a more flexible Item type that can cover various scenarios
export type DirectusItemType =
  | { id: DirectusIdType }
  | DirectusIdType
  | undefined
  | null;

export type DirectusItemIntoRelation<T extends DirectusItemType> =
  | RelationType<T>
  | RelationType<T>["id"];

export type RelationIdType<T extends DirectusItemType> = Exclude<
  T extends { id: infer U } ? U : T,
  { id?: DirectusIdType }
>;

export type RelationType<T extends DirectusItemType> = Exclude<
  T,
  string | number | null | undefined
>;

export type DirectusItemExcludeRelations<T extends DirectusItemType> =
  | Exclude<T, { id: DirectusIdType }>
  | RelationIdType<T>;

// Refactor the getItemId function to use a more straightforward generic approach
export function getItemId<T extends DirectusItemType>(
  item: T,
): RelationIdType<T> {
  if (typeof item === "object" && item !== null && "id" in item) {
    // Explicitly cast the return type based on the conditional type
    return item.id as RelationIdType<T>;
  }
  // Handle cases where item is not an object or doesn't have an 'id' property
  return item as RelationIdType<T>;
}

export function getFileUrl<Schema>(
  directus: DirectusClient<Schema>,
  item?: DirectusItemType,
  options?: DirectusFileNamespace.Props,
) {
  if (!item) return;
  const searchParams = new URLSearchParams();
  if (options?.accessToken) {
    searchParams.set("access_token", options.accessToken);
  }
  if (options?.download) {
    searchParams.set("download", "");
  }
  if ("string" === typeof options?.directusTransform) {
    searchParams.set("directus_transform", options.directusTransform);
  } else if ("object" === typeof options?.directusTransform) {
    // Adds all the custom transforms to the params
    for (const [key, value] of Object.entries(options?.directusTransform)) {
      if (value) {
        searchParams.append(key, value.toString());
      }
    }
  }
  return `${directus.url}assets/${getItemId(item)}${options?.filename ? "/" + options?.filename : ""}?${searchParams.toString()}`;
}

export function useFileUrl<
  Schema,
  DirectusInstance extends DirectusClient<Schema>,
>(directus: DirectusInstance, globalOptions?: DirectusFileNamespace.Props) {
  return (item?: DirectusItemType, options?: DirectusFileNamespace.Props) =>
    getFileUrl(directus, item, {
      ...globalOptions,
      ...options,
    });
}

export function getRelation<
  T extends string | number | object | null | undefined,
  R extends boolean,
>(
  relation: T,
  required?: R,
): T extends object | null | undefined
  ? R extends true
    ? NonNullable<T>
    : T
  : never {
  if (required) {
    if (relation === null || relation === undefined) {
      throw new Error("relation is not loaded");
    }
  }
  if (relation === undefined || typeof relation === "object") {
    return relation as T extends object | null | undefined
      ? R extends true
        ? NonNullable<T>
        : T
      : never;
  }
  throw new Error("relation is not loaded");
}

export function getStringDate<
  T extends Types.Date | Types.DateTime | null | undefined,
>(date: T) {
  return date as Exclude<T, Date>;
}

export type TypedDirectusClient = DirectusClient<Schema>;
export { DirectusFileNamespace };

export type ToSafeOutput<Output> =
  | {
      data: Output;
      isError: false;
      error: never;
    }
  | {
      error: Error;
      isError: true;
      data: never;
    };

export const toSafe = <Output,>(
  promise: Promise<Output>,
): Promise<ToSafeOutput<Output>> => {
  return promise
    .then(
      (data) =>
        ({ data, isError: false }) as {
          data: typeof data;
          isError: false;
          error: never;
        },
    )
    .catch(
      (error) =>
        ({ error, isError: true }) as {
          error: Error;
          isError: true;
          data: never;
        },
    );
};
