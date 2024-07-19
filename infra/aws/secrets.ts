import { Item, item, validateCli } from "@1password/op-js";
import * as aws from "@pulumi/aws";
import * as pulumi from "@pulumi/pulumi";

type GetPasswordManagerDataParams = {
  vault: string;
  repo: string;
  env: string;
  section?: string;
  type: "secrets" | "env";
};

type GetEnvironmentVarsParams = Omit<GetPasswordManagerDataParams, "type">;

type SyncSecretsAndGetRefsParams = GetEnvironmentVarsParams & {
  targetSecretArn: string;
};

type EnvironmentVar = { name: string; value: string };
type SecretRef = { name: string; valueFrom: string };

// Given a 1P definition and a target secret ARN, sync the secrets to the target secret
// object in AWS Secrets Manager and return the references to those secret values
export const syncSecretsAndGetRefs = (
  params: SyncSecretsAndGetRefsParams
): SecretRef[] => {
  const { targetSecretArn, ...passwordManagerParams } = params;

  const secretDefinitions = getPasswordManagerData({
    ...passwordManagerParams,
    type: "secrets",
  });

  const secretString = JSON.stringify(
    secretDefinitions.reduce((acc, { name, value }) => {
      acc[name] = value;
      return acc;
    }, {} as Record<string, string>)
  );

  new aws.secretsmanager.SecretVersion(
    `${targetSecretArn.split(":").slice(-1)}-secret-version`,
    {
      secretId: targetSecretArn,
      secretString,
      versionStages: ["AWSCURRENT"],
    }
  );

  return secretDefinitions.map(({ name }) => ({
    name,
    valueFrom: `${targetSecretArn}:${name}::`,
  }));
};

// Given a 1P definition, return the environment variables
export const getEnvironmentVars = (
  params: GetEnvironmentVarsParams
): EnvironmentVar[] => {
  return getPasswordManagerData({ ...params, type: "env" });
};

const password_manager_ci_validated = false;

const getPasswordManagerData = ({
  vault,
  repo,
  env,
  type,
  section,
}: GetPasswordManagerDataParams): EnvironmentVar[] => {
  password_manager_ci_validated || validateCli();

  const noteName = `${repo}-${env}-${type}`;

  const envNote = item.get(noteName, { vault }) as Item;

  const fields =
    (section
      ? envNote.fields?.filter((field) => field.section?.label === section)
      : envNote.fields) || [];

  if (!fields.length) {
    throw new Error(
      `No data found for ${vault}/${repo}-${env}-${type}${
        section ? `/${section}` : ""
      }`
    );
  }

  return fields
    .map(({ label, value }) => ({ name: label, value }))
    .sort(sortByName);
};

// Pulumi sorts alphabetically by name, so we want to match so that
// the diff doesn't falsely show differences because of the order.
// This is used above to pre-sort. But if you add to any of these
// arrays, you'll want to sort the final array as well
export const sortByName = (a: { name: string }, b: { name: string }) =>
  a.name.localeCompare(b.name);
