import React from "react";
import { signedPdfUrl } from "../api/client";

type Props = {
  fileId: string;
};

export function DownloadSignedPdfButton({ fileId }: Props) {
  return (
    <a className="download-button" href={signedPdfUrl(fileId)} download>
      Download signed PDF
    </a>
  );
}
